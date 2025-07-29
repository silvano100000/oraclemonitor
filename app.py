# app.py

import os
import datetime
import threading
import time
import json
import cx_Oracle # Certifique-se de que cx_Oracle está importado
import configparser
import sys
import traceback
import sqlite3
import subprocess # Importado para demonstrar a execução de comandos externos

from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Variável global para armazenar todas as configurações de banco de dados por TNS alias
# Ex: DB_CONFIGS = {'tns1': {...}, 'tns2': {...}}
DB_CONFIGS = {}
EXCLUDED_TABLESPACES = {} # Agora um dicionário por TNS alias
EXCLUDED_SCHEMAS = {}     # Agora um dicionário de sets por TNS alias

# Flags de UI (mantidas globais, mas agora podem ser default para todos os TNS, ou por TNS se necessário)
ENABLE_ACTIVE_SESSIONS = True
ENABLE_INSTANCE_HEALTH = True
ENABLE_SESSION_STATUS_BOX = True
ENABLE_TOP_USERS_BOX = True
ENABLE_TOP_PROGRAMS_BOX = True
ENABLE_WAITING_SESSIONS = True
ENABLE_BLOCKED_SESSIONS = True

# Global Threshold Variables
TABLESPACE_WARNING_PERCENT = 80
TABLESPACE_CRITICAL_PERCENT = 90
SCHEMA_WARNING_GB = 50
SCHEMA_CRITICAL_GB = 100

# SSL Configuration Variables
SSL_ENABLED = False
SSL_CERT_PATH = ''
SSL_KEY_PATH = ''

# Admin Security Variable
ADMIN_PASSWORD = '' # This will be loaded from config.ini

# Application Version
APP_VERSION = "2.0.9" # Versão atualizada para log de backup real

# Dicionário para armazenar o status de operações de drop de schema
# Chave: schema_name, Valor: {'status': 'IN_PROGRESS'/'COMPLETED'/'FAILED', 'message': '...'}.
SCHEMA_DROP_STATUS = {}

# Dicionário para armazenar o status dos backups (apenas para demonstração)
# Em uma aplicação real, você usaria um banco de dados (como history.db) para persistir isso
backup_statuses = {}

# SQLite Database Path
HISTORY_DB_PATH = 'history.db'

def init_history_db():
    """
    Inicializa o banco de dados SQLite e cria as tabelas de histórico e log se não existirem.
    """
    conn = None
    try:
        conn = sqlite3.connect(HISTORY_DB_PATH)
        cursor = conn.cursor()

        # Tabela para histórico de uso de schemas
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_history (
                tns_alias TEXT NOT NULL,
                schema_name TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                used_gb REAL NOT NULL,
                PRIMARY KEY (tns_alias, schema_name, timestamp)
            )
        """)

        # Tabela para histórico de uso de tablespaces
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tablespace_history (
                tns_alias TEXT NOT NULL,
                tablespace_name TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                used_percent REAL NOT NULL,
                PRIMARY KEY (tns_alias, tablespace_name, timestamp)
            )
        """)

        # Tabela para log de alterações de schemas
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_change_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tns_alias TEXT NOT NULL,
                schema_name TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                change_type TEXT NOT NULL,
                description TEXT NOT NULL,
                changed_by TEXT NOT NULL
            )
        """)
        conn.commit()
        print(f"Banco de dados SQLite '{HISTORY_DB_PATH}' inicializado com sucesso.", file=sys.stderr)
    except sqlite3.Error as e:
        print(f"Erro ao inicializar o banco de dados SQLite: {e}", file=sys.stderr)
        traceback.print_exc()
        raise RuntimeError(f"Falha ao inicializar o banco de dados SQLite: {e}")
    finally:
        if conn:
            conn.close()

def log_schema_history(tns_alias, schema_name, used_gb):
    """
    Registra o uso de espaço de um schema no banco de dados SQLite.
    """
    conn = None
    try:
        conn = sqlite3.connect(HISTORY_DB_PATH)
        cursor = conn.cursor()
        timestamp = datetime.datetime.now().isoformat()
        cursor.execute("""
            INSERT OR REPLACE INTO schema_history (tns_alias, schema_name, timestamp, used_gb)
            VALUES (?, ?, ?, ?)
        """, (tns_alias, schema_name, timestamp, used_gb))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Erro ao registrar histórico do schema no SQLite: {e}", file=sys.stderr)
        traceback.print_exc()
    finally:
        if conn:
            conn.close()

def log_tablespace_history(tns_alias, tablespace_name, used_percent):
    """
    Registra o uso de porcentagem de um tablespace no banco de dados SQLite.
    """
    conn = None
    try:
        conn = sqlite3.connect(HISTORY_DB_PATH)
        cursor = conn.cursor()
        timestamp = datetime.datetime.now().isoformat()
        cursor.execute("""
            INSERT OR REPLACE INTO tablespace_history (tns_alias, tablespace_name, timestamp, used_percent)
            VALUES (?, ?, ?, ?)
        """, (tns_alias, tablespace_name, timestamp, used_percent))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Erro ao registrar histórico do tablespace no SQLite: {e}", file=sys.stderr)
        traceback.print_exc()
    finally:
        if conn:
            conn.close()

def add_change_log_entry(tns_alias, schema_name, change_type, description, changed_by="System/Admin"):
    """
    Adiciona uma entrada ao log de alterações de schemas no banco de dados SQLite.
    """
    conn = None
    try:
        conn = sqlite3.connect(HISTORY_DB_PATH)
        cursor = conn.cursor()
        timestamp = datetime.datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO schema_change_log (tns_alias, schema_name, timestamp, change_type, description, changed_by)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (tns_alias, schema_name, timestamp, change_type, description, changed_by))
        conn.commit()
        print(f"Log de auditoria adicionado ao SQLite: TNS='{tns_alias}', Schema='{schema_name}', Tipo='{change_type}'", file=sys.stderr)
    except sqlite3.Error as e:
        print(f"Erro ao registrar log de alterações no SQLite: {e}", file=sys.stderr)
        traceback.print_exc()
    finally:
        if conn:
            conn.close()

def get_oracle_version_from_conn(conn):
    """
    Obtém a versão do Oracle (major.minor) de uma conexão.
    Retorna 0.0 em caso de erro ou se a versão não puder ser parseada.
    """
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT version FROM v$instance")
        version_str = cursor.fetchone()[0]
        parts = version_str.split('.')
        if len(parts) >= 2:
            return float(f"{parts[0]}.{parts[1]}")
        return 0.0
    except Exception as e:
        print(f"Erro ao buscar a versão do Oracle: {e}", file=sys.stderr)
        return 0.0
    finally:
        if cursor:
            cursor.close()

def load_db_config():
    """
    Carrega as configurações do banco de dados e UI do arquivo config.ini.
    """
    global DB_CONFIGS, EXCLUDED_TABLESPACES, EXCLUDED_SCHEMAS, \
           ENABLE_ACTIVE_SESSIONS, ENABLE_INSTANCE_HEALTH, ENABLE_SESSION_STATUS_BOX, \
           ENABLE_TOP_USERS_BOX, ENABLE_TOP_PROGRAMS_BOX, ENABLE_WAITING_SESSIONS, \
           ENABLE_BLOCKED_SESSIONS, TABLESPACE_WARNING_PERCENT, TABLESPACE_CRITICAL_PERCENT, \
           SCHEMA_WARNING_GB, SCHEMA_CRITICAL_GB, SSL_ENABLED, SSL_CERT_PATH, SSL_KEY_PATH, \
           ADMIN_PASSWORD

    config = configparser.ConfigParser()
    config_file_path = 'config.ini'

    if not os.path.exists(config_file_path):
        raise FileNotFoundError(f"O arquivo '{config_file_path}' não foi encontrado.")

    try:
        config.read(config_file_path)
    except configparser.Error as e:
        raise configparser.Error(f"Erro ao analisar o arquivo config.ini: {e}")

    # Carregar configurações de cada TNS
    for section in config.sections():
        if section.startswith('tns:'):
            tns_alias = section.split('tns:')[1]
            db_config = {
                'user': config.get(section, 'user'),
                'password': config.get(section, 'password'),
                'host': config.get(section, 'host'),
                'port': config.get(section, 'port'),
                'service_name': config.get(section, 'service_name')
            }

            # Tenta conectar temporariamente para obter a versão do Oracle
            temp_conn = None
            try:
                temp_conn = cx_Oracle.connect(user=db_config['user'], password=db_config['password'], dsn=cx_Oracle.makedsn(db_config['host'], db_config['port'], service_name=db_config['service_name']))
                db_config['oracle_version'] = get_oracle_version_from_conn(temp_conn)
                print(f"Versão do Oracle detectada para {tns_alias}: {db_config['oracle_version']}", file=sys.stderr)
            except Exception as e:
                print(f"Não foi possível determinar a versão do Oracle para {tns_alias}: {e}. Assumindo versão antiga (pré-12.1).", file=sys.stderr)
                db_config['oracle_version'] = 0.0 # Assume versão antiga se não puder determinar
            finally:
                if temp_conn:
                    temp_conn.close()

            DB_CONFIGS[tns_alias] = db_config

            # Carregar tablespaces excluídos para este TNS
            excluded_ts_str = config.get(section, 'excluded_tablespaces', fallback='')
            EXCLUDED_TABLESPACES[tns_alias] = [ts.strip().upper() for ts in excluded_ts_str.split(',') if ts.strip()]

            # Carregar schemas excluídos para este TNS
            excluded_schemas_str = config.get(section, 'excluded_schemas', fallback='')
            EXCLUDED_SCHEMAS[tns_alias] = {s.strip().upper() for s in excluded_schemas_str.split(',') if s.strip()}

            # Carregar thresholds específicos do TNS, se existirem
            TABLESPACE_WARNING_PERCENT = config.getint(section, 'tablespace_warning_percent', fallback=80)
            TABLESPACE_CRITICAL_PERCENT = config.getint(section, 'tablespace_critical_percent', fallback=90)
            SCHEMA_WARNING_GB = config.getint(section, 'schema_warning_gb', fallback=50)
            SCHEMA_CRITICAL_GB = config.getint(section, 'schema_critical_gb', fallback=100)


    # Carregar configurações de UI (seção [ui_features])
    if 'ui_features' in config:
        ENABLE_ACTIVE_SESSIONS = config.getboolean('ui_features', 'enable_active_sessions', fallback=True)
        ENABLE_INSTANCE_HEALTH = config.getboolean('ui_features', 'enable_instance_health', fallback=True)
        ENABLE_SESSION_STATUS_BOX = config.getboolean('ui_features', 'enable_session_status_box', fallback=True)
        ENABLE_TOP_USERS_BOX = config.getboolean('ui_features', 'enable_top_users_box', fallback=True)
        ENABLE_TOP_PROGRAMS_BOX = config.getboolean('ui_features', 'enable_top_programs_box', fallback=True)
        ENABLE_WAITING_SESSIONS = config.getboolean('ui_features', 'enable_waiting_sessions', fallback=True)
        ENABLE_BLOCKED_SESSIONS = config.getboolean('ui_features', 'enable_blocked_sessions', fallback=True)

    # Carregar configurações SSL
    if 'ssl_config' in config:
        SSL_ENABLED = config.getboolean('ssl_config', 'ssl_enabled', fallback=False)
        SSL_CERT_PATH = config.get('ssl_config', 'ssl_cert_path', fallback='')
        SSL_KEY_PATH = config.get('ssl_config', 'ssl_key_path', fallback='')

    # Carregar senha administrativa
    if 'admin_security' in config:
        ADMIN_PASSWORD = config.get('admin_security', 'admin_password', fallback='admin')
        if not ADMIN_PASSWORD:
            raise ValueError("A senha administrativa não pode estar vazia em config.ini na seção [admin_security].")

    if not DB_CONFIGS:
        raise RuntimeError("Nenhuma configuração de banco de dados encontrada em config.ini. Certifique-se de ter seções [tns:seu_alias].")

def get_db_connection(tns_alias):
    """
    Estabelece uma conexão com o banco de dados Oracle usando as configurações para o TNS alias fornecido.
    """
    db_config = DB_CONFIGS.get(tns_alias)
    if not db_config:
        raise ValueError(f"Configuração para TNS alias '{tns_alias}' não encontrada.")

    dsn = cx_Oracle.makedsn(db_config['host'], db_config['port'], service_name=db_config['service_name'])
    try:
        connection = cx_Oracle.connect(user=db_config['user'], password=db_config['password'], dsn=dsn)
        return connection
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Erro ao conectar ao banco de dados Oracle para {tns_alias}: {error_obj.message}", file=sys.stderr)
        traceback.print_exc()
        raise RuntimeError(f"Falha na conexão com o banco de dados para {tns_alias}: {error_obj.message}")

def get_status_by_percent(used_percent, tns_alias):
    """Determina o status (NORMAL, WARNING, CRITICAL) com base na porcentagem de uso."""
    if tns_alias not in DB_CONFIGS:
        return "UNKNOWN" # Or raise an error, depending on desired behavior

    # Use TNS-specific thresholds if available, otherwise global defaults
    # Note: These are loaded once per TNS in load_db_config.
    warning_threshold = DB_CONFIGS[tns_alias].get('tablespace_warning_percent', TABLESPACE_WARNING_PERCENT)
    critical_threshold = DB_CONFIGS[tns_alias].get('tablespace_critical_percent', TABLESPACE_CRITICAL_PERCENT)

    if used_percent >= critical_threshold:
        return "CRITICAL"
    elif used_percent >= warning_threshold:
        return "WARNING"
    else:
        return "NORMAL"

def get_status_by_gb(used_gb, tns_alias):
    """Determina o status (NORMAL, WARNING, CRITICAL) com base no uso em GB."""
    if tns_alias not in DB_CONFIGS:
        return "UNKNOWN" # Or raise an error

    # Use TNS-specific thresholds if available, otherwise global defaults
    # Note: These are loaded once per TNS in load_db_config.
    warning_threshold_gb = DB_CONFIGS[tns_alias].get('schema_warning_gb', SCHEMA_WARNING_GB)
    critical_threshold_gb = DB_CONFIGS[tns_alias].get('schema_critical_gb', SCHEMA_CRITICAL_GB)

    if used_gb >= critical_threshold_gb:
        return "CRITICAL"
    elif used_gb >= warning_threshold_gb:
        return "WARNING"
    else:
        return "NORMAL"


# --- API Endpoints ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/tns_list', methods=['GET'])
def tns_list():
    """Retorna a lista de TNS aliases configurados."""
    return jsonify(list(DB_CONFIGS.keys()))

@app.route('/api/config', methods=['GET'])
def get_ui_config():
    """Retorna as configurações de UI."""
    return jsonify({
        'enable_active_sessions': ENABLE_ACTIVE_SESSIONS,
        'enable_instance_health': ENABLE_INSTANCE_HEALTH,
        'enable_session_status_box': ENABLE_SESSION_STATUS_BOX,
        'enable_top_users_box': ENABLE_TOP_USERS_BOX,
        'enable_top_programs_box': ENABLE_TOP_PROGRAMS_BOX,
        'enable_waiting_sessions': ENABLE_WAITING_SESSIONS,
        'enable_blocked_sessions': ENABLE_BLOCKED_SESSIONS
    })

@app.route('/api/db_space', methods=['GET'])
def db_space():
    """Retorna o espaço total, livre e usado do banco de dados."""
    tns_alias = request.args.get('tns_alias')
    if not tns_alias:
        return jsonify({"error": "TNS alias is required."}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()
        # Query corrigida para obter total alocado e total livre de diferentes views
        cursor.execute("""
            SELECT
                (SELECT SUM(bytes) FROM dba_data_files) / 1024 / 1024 / 1024 AS total_allocated_gb,
                (SELECT SUM(bytes) FROM dba_free_space) / 1024 / 1024 / 1024 AS free_bytes_gb
            FROM
                dual
        """)
        row = cursor.fetchone()

        total_gb = row[0] if row[0] else 0
        free_gb = row[1] if row[1] else 0

        used_gb = total_gb - free_gb
        used_percent = (used_gb / total_gb) * 100 if total_gb > 0 else 0

        return jsonify({
            "total_gb": total_gb,
            "free_gb": free_gb,
            "used_gb": used_gb,
            "used_percent": used_percent
        })
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/tablespace_space', methods=['GET'])
def tablespace_space():
    """Retorna o espaço usado e livre por tablespace."""
    tns_alias = request.args.get('tns_alias')
    if not tns_alias:
        return jsonify({"error": "TNS alias is required."}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()

        # Query corrigida para obter o espaço total (bytes atuais) e espaço livre por tablespace
        # usando subconsultas para evitar multiplicação de linhas.
        sql_query = """
            SELECT
                t.tablespace_name,
                ROUND(total.total_bytes / 1024 / 1024 / 1024, 2) AS total_gb,
                ROUND(NVL(free.free_bytes, 0) / 1024 / 1024 / 1024, 2) AS free_gb
            FROM
                dba_tablespaces t
            LEFT JOIN (
                SELECT
                    tablespace_name,
                    SUM(bytes) AS total_bytes
                FROM
                    dba_data_files
                GROUP BY
                    tablespace_name
            ) total ON t.tablespace_name = total.tablespace_name
            LEFT JOIN (
                SELECT
                    tablespace_name,
                    SUM(bytes) AS free_bytes
                FROM
                    dba_free_space
                GROUP BY
                    tablespace_name
            ) free ON t.tablespace_name = free.tablespace_name
            WHERE
                total.total_bytes IS NOT NULL -- Exclui tablespaces sem datafiles (ex: temp, undo)
            ORDER BY
                t.tablespace_name
        """
        print(f"DEBUG: Executando SQL para tablespace_space: {sql_query}", file=sys.stderr)
        cursor.execute(sql_query)

        tablespace_data = []
        excluded_tablespaces = EXCLUDED_TABLESPACES.get(tns_alias, [])
        for row in cursor:
            name = row[0]
            if name.upper() in excluded_tablespaces:
                continue

            total_gb = row[1] if row[1] else 0
            free_gb = row[2] if row[2] else 0
            used_gb = total_gb - free_gb
            used_percent = (used_gb / total_gb) * 100 if total_gb > 0 else 0

            print(f"DEBUG: Tablespace: {name}, Total GB (raw): {row[1]}, Free GB (raw): {row[2]}, Used GB (calc): {used_gb}, Used Percent (calc): {used_percent}", file=sys.stderr)


            tablespace_data.append({
                "name": name,
                "total_gb": round(total_gb, 2),
                "free_gb": round(free_gb, 2),
                "used_gb": round(used_gb, 2),
                "used_percent": round(used_percent, 2),
                "status": get_status_by_percent(used_percent, tns_alias)
            })
        return jsonify(tablespace_data)
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/tablespace_details', methods=['GET'])
def tablespace_details():
    """Retorna detalhes de um tablespace específico, incluindo datafiles e top objetos."""
    tns_alias = request.args.get('tns_alias')
    tablespace_name = request.args.get('name')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    if not tns_alias or not tablespace_name:
        return jsonify({"error": "TNS alias and tablespace name are required."}), 400

    conn = None
    cursor = None
    sqlite_conn = None
    sqlite_cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()

        # Datafiles
        # Adicionado NVL para bytes e maxbytes para garantir que sejam números
        cursor.execute("""
            SELECT
                file_name,
                NVL(bytes, 0) / 1024 / 1024 / 1024 AS size_gb,
                NVL(maxbytes, 0) / 1024 / 1024 / 1024 AS max_size_gb,
                autoextensible
            FROM
                dba_data_files
            WHERE
                tablespace_name = :tablespace_name
            ORDER BY
                file_name
        """, tablespace_name=tablespace_name)
        datafiles = [{"file_name": r[0], "size_gb": round(r[1], 2), "max_size_gb": round(r[2], 2), "autoextensible": r[3]} for r in cursor]

        # Determine Oracle version for conditional SQL
        oracle_version = DB_CONFIGS.get(tns_alias, {}).get('oracle_version', 0.0)

        # Top 10 Objects by Size in the Tablespace
        # Conditional SQL for FETCH FIRST (12c+) vs ROWNUM (11g-)
        # Adicionado NVL para bytes para garantir que seja um número
        sql_top_objects_tablespace = f"""
            SELECT
                owner,
                segment_name,
                segment_type,
                NVL(bytes, 0) / 1024 / 1024 AS size_mb
            FROM
                dba_segments
            WHERE
                tablespace_name = :tablespace_name
            ORDER BY
                bytes DESC
        """
        if oracle_version < 12.1:
            sql_top_objects_tablespace = f"SELECT * FROM ({sql_top_objects_tablespace}) WHERE ROWNUM <= 10"
        else:
            sql_top_objects_tablespace += " FETCH FIRST 10 ROWS ONLY"

        cursor.execute(sql_top_objects_tablespace, tablespace_name=tablespace_name)
        top_objects = [{"owner": r[0], "segment_name": r[1], "segment_type": r[2], "size_mb": round(r[3], 2)} for r in cursor]

        # Fetch current tablespace usage percentage to log
        cursor.execute("""
            SELECT
                (total.bytes_alloc - free.bytes_free) * 100 / total.bytes_alloc AS used_percent
            FROM
                ( SELECT tablespace_name, SUM(bytes) bytes_alloc FROM dba_data_files GROUP BY tablespace_name ) total
            JOIN
                ( SELECT tablespace_name, SUM(bytes) bytes_free FROM dba_free_space GROUP BY tablespace_name ) free
            ON total.tablespace_name = free.tablespace_name
            WHERE total.tablespace_name = :tablespace_name
        """, tablespace_name=tablespace_name)
        current_ts_percent_row = cursor.fetchone()
        current_used_percent = current_ts_percent_row[0] if current_ts_percent_row and current_ts_percent_row[0] else 0.0

        # Log current tablespace usage to SQLite
        log_tablespace_history(tns_alias, tablespace_name, current_used_percent)

        # Retrieve historical data from SQLite
        sqlite_conn = sqlite3.connect(HISTORY_DB_PATH)
        sqlite_cursor = sqlite_conn.cursor()

        history_query = """
            SELECT timestamp, used_percent
            FROM tablespace_history
            WHERE tns_alias = ? AND tablespace_name = ?
        """
        query_params = [tns_alias, tablespace_name]

        if start_date_str:
            history_query += " AND timestamp >= ?"
            query_params.append(start_date_str)
        if end_date_str:
            history_query += " AND timestamp <= ?"
            query_params.append(end_date_str)

        history_query += " ORDER BY timestamp"

        sqlite_cursor.execute(history_query, tuple(query_params))
        history_data = [{"timestamp": r[0], "used_percent": r[1]} for r in sqlite_cursor.fetchall()]

        return jsonify({
            "datafiles": datafiles,
            "top_objects": top_objects,
            "history_data": history_data
        })
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error fetching tablespace details: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
        if sqlite_cursor:
            sqlite_cursor.close()
        if sqlite_conn:
            sqlite_conn.close()

@app.route('/api/add_datafile', methods=['POST'])
def add_datafile():
    """Adiciona um novo datafile a um tablespace."""
    tns_alias = request.json.get('tns_alias')
    tablespace_name = request.json.get('tablespace_name')
    file_name = request.json.get('file_name')
    size_value = request.json.get('size_value')
    size_unit = request.json.get('size_unit')
    autoextend = request.json.get('autoextend')
    next_size_value = request.json.get('next_size_value')
    next_size_unit = request.json.get('next_size_unit')
    max_size_value = request.json.get('max_size_value')
    max_size_unit = request.json.get('max_size_unit')
    admin_password = request.json.get('admin_password')

    if admin_password != ADMIN_PASSWORD:
        return jsonify({"error": "Senha administrativa incorreta."}), 403

    if not all([tns_alias, tablespace_name, file_name, size_value, size_unit]):
        return jsonify({"error": "Dados insuficientes para adicionar datafile."}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()

        size_clause = f"{size_value}{size_unit}"
        autoextend_clause = ""
        if autoextend:
            autoextend_clause = "AUTOEXTEND ON"
            if next_size_value:
                autoextend_clause += f" NEXT {next_size_value}{next_size_unit}"
            if max_size_value:
                autoextend_clause += f" MAXSIZE {max_size_value}{max_size_unit}"
            else:
                autoextend_clause += " UNLIMITED"

        sql = f"ALTER TABLESPACE {tablespace_name} ADD DATAFILE '{file_name}' SIZE {size_clause} {autoextend_clause}"
        print(f"Executing SQL: {sql}") # Log the SQL for debugging
        cursor.execute(sql)
        conn.commit()
        return jsonify({"message": "Datafile adicionado com sucesso."}), 200
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error adding datafile: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/resize_datafile', methods=['POST'])
def resize_datafile():
    """Redimensiona ou configura o autoextend para um datafile."""
    tns_alias = request.json.get('tns_alias')
    file_name = request.json.get('file_name')
    new_size_value = request.json.get('new_size_value')
    new_size_unit = request.json.get('new_size_unit')
    autoextend = request.json.get('autoextend')
    next_size_value = request.json.get('next_size_value')
    next_size_unit = request.json.get('next_size_unit')
    max_size_value = request.json.get('max_size_value')
    max_size_unit = request.json.get('max_size_unit')
    admin_password = request.json.get('admin_password')

    if admin_password != ADMIN_PASSWORD:
        return jsonify({"error": "Senha administrativa incorreta."}), 403

    if not all([tns_alias, file_name]) or (new_size_value is None and not autoextend):
        return jsonify({"error": "Dados insuficientes para redimensionar/configurar datafile."}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()

        sql_parts = []
        if new_size_value is not None:
            sql_parts.append(f"RESIZE {new_size_value}{new_size_unit}")

        if autoextend:
            autoextend_clause = "AUTOEXTEND ON"
            if next_size_value:
                autoextend_clause += f" NEXT {next_size_value}{next_size_unit}"
            if max_size_value:
                autoextend_clause += f" MAXSIZE {max_size_value}{max_size_unit}"
            else:
                autoextend_clause += " UNLIMITED"
            sql_parts.append(autoextend_clause)
        else:
            sql_parts.append("AUTOEXTEND OFF")

        sql = f"ALTER DATABASE DATAFILE '{file_name}' {' '.join(sql_parts)}"
        print(f"Executing SQL: {sql}") # Log the SQL for debugging
        cursor.execute(sql)
        conn.commit()
        return jsonify({"message": "Datafile redimensionado/configurado com sucesso."}), 200
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error resizing datafile: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/api/all_schemas', methods=['GET'])
def all_schemas():
    """Retorna o espaço usado por cada schema (utilizador) e o status da conta, incluindo schemas sem espaço."""
    tns_alias = request.args.get('tns_alias')
    if not tns_alias:
        return jsonify({"error": "TNS alias is required."}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()

        # Query modificada para incluir todos os schemas (dba_users) e fazer LEFT JOIN com dba_segments
        sql_query = """
            SELECT
                u.username AS owner,
                NVL(SUM(s.bytes), 0) / 1024 / 1024 / 1024 AS used_gb,
                u.account_status
            FROM
                dba_users u
            LEFT JOIN
                dba_segments s ON u.username = s.owner
            GROUP BY
                u.username, u.account_status
            ORDER BY
                u.username
        """
        print(f"DEBUG: Executando SQL para all_schemas: {sql_query}", file=sys.stderr)
        cursor.execute(sql_query)

        schema_data = []
        excluded_schemas = EXCLUDED_SCHEMAS.get(tns_alias, set())
        for row in cursor:
            schema_name = row[0]
            if schema_name.upper() in excluded_schemas:
                continue

            used_gb = row[1] if row[1] else 0
            account_status = row[2]
            status_color = get_status_by_gb(used_gb, tns_alias)

            # Check for ongoing backup status and override if necessary
            if backup_statuses.get(schema_name, {}).get("status") in ["backup em andamento", "iniciando backup"]:
                account_status = "backup em andamento"
                status_color = "NORMAL" # Or a specific color for backup

            print(f"DEBUG: Schema: {schema_name}, Used GB (raw): {row[1]}, Account Status: {account_status}, Status (calc): {status_color}", file=sys.stderr)

            schema_data.append({
                "name": schema_name,
                "used_gb": round(used_gb, 2),
                "status": status_color,
                "account_status": account_status
            })
        return jsonify(schema_data)
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/schema_details', methods=['GET'])
def schema_details():
    """
    Retorna detalhes de um schema específico, incluindo grants e top objetos.
    Agora aceita um parâmetro 'object_type' para filtrar os top objetos.
    """
    tns_alias = request.args.get('tns_alias')
    schema_name = request.args.get('name')
    object_type_filter = request.args.get('object_type') # Novo parâmetro de filtro

    if not tns_alias or not schema_name:
        return jsonify({"error": "TNS alias and schema name are required."}), 400

    conn = None
    cursor = None
    sqlite_conn = None
    sqlite_cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()

        # Schema Info (creation date, account status, default tablespace)
        cursor.execute("""
            SELECT
                created,
                account_status,
                default_tablespace
            FROM
                dba_users
            WHERE
                username = :schema_name
        """, schema_name=schema_name)
        schema_info = cursor.fetchone()
        creation_date = schema_info[0].strftime('%Y-%m-%d %H:%M:%S') if schema_info and schema_info[0] else 'N/A'
        account_status = schema_info[1] if schema_info and schema_info[1] else 'N/A'
        default_tablespace = schema_info[2] if schema_info and schema_info[2] else 'N/A' # Adicionado

        # Role Grants
        cursor.execute("""
            SELECT
                granted_role,
                admin_option
            FROM
                dba_role_privs
            WHERE
                grantee = :schema_name
            ORDER BY
                granted_role
        """, schema_name=schema_name)
        role_grants = [{"privilege": r[0], "admin_option": r[1]} for r in cursor]

        # System Privileges
        cursor.execute("""
            SELECT
                privilege,
                admin_option
            FROM
                dba_sys_privs
            WHERE
                grantee = :schema_name
            ORDER BY
                privilege
        """, schema_name=schema_name)
        sys_grants = [{"privilege": r[0], "admin_option": r[1]} for r in cursor]

        # Object Privileges (Table Grants)
        cursor.execute("""
            SELECT
                owner,
                table_name,
                privilege,
                grantable
            FROM
                dba_tab_privs
            WHERE
                grantee = :schema_name
            ORDER BY
                owner, table_name, privilege
        """, schema_name=schema_name)
        tab_grants = [{"owner": r[0], "table_name": r[1], "privilege": r[2], "grantable": r[3]} for r in cursor]

        # Determine Oracle version for conditional SQL
        oracle_version = DB_CONFIGS.get(tns_alias, {}).get('oracle_version', 0.0)

        # Top 10 Objects (Tables/Indexes) by Size for this schema
        # Conditional SQL for FETCH FIRST (12c+) vs ROWNUM (11g-)
        sql_top_objects_schema = f"""
            SELECT
                owner,
                segment_name,
                segment_type,
                NVL(bytes, 0) / 1024 / 1024 AS size_mb
            FROM
                dba_segments
            WHERE
                owner = :schema_name -- Corrected from tablespace_name to owner
        """
        # Adiciona o filtro por tipo de objeto se fornecido e não for 'ALL'
        if object_type_filter and object_type_filter.upper() != 'ALL':
            sql_top_objects_schema += f" AND segment_type = '{object_type_filter.upper()}'"

        sql_top_objects_schema += " ORDER BY bytes DESC"

        if oracle_version < 12.1:
            sql_top_objects_schema = f"SELECT * FROM ({sql_top_objects_schema}) WHERE ROWNUM <= 10"
        else:
            sql_top_objects_schema += " FETCH FIRST 10 ROWS ONLY"

        cursor.execute(sql_top_objects_schema, schema_name=schema_name)
        top_objects = [{"owner": r[0], "segment_name": r[1], "segment_type": r[2], "size_mb": round(r[3], 2)} for r in cursor]

        # Object Counts by Type for this schema
        cursor.execute("""
            SELECT
                object_type,
                COUNT(*) AS count
            FROM
                dba_objects
            WHERE
                owner = :schema_name
            GROUP BY
                object_type
            ORDER BY
                object_type
        """, schema_name=schema_name)
        object_counts = [{"object_type": r[0], "count": r[1]} for r in cursor]


        return jsonify({
            "creation_date": creation_date,
            "account_status": account_status,
            "default_tablespace": default_tablespace, # Adicionado
            "role_grants": role_grants,
            "sys_grants": sys_grants,
            "tab_grants": tab_grants,
            "top_objects": top_objects,
            "object_counts": object_counts
        })
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error fetching schema details: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
        if sqlite_cursor:
            sqlite_cursor.close()
        if sqlite_conn:
            sqlite_conn.close()

@app.route('/api/schema_history', methods=['GET'])
def schema_history():
    """
    Retorna o histórico de uso de espaço para um schema do banco de dados SQLite.
    Aceita parâmetros start_date e end_date para filtragem.
    """
    tns_alias = request.args.get('tns_alias')
    schema_name = request.args.get('name')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    if not tns_alias or not schema_name:
        return jsonify({"error": "TNS alias and schema name are required."}), 400

    oracle_conn = None
    oracle_cursor = None
    sqlite_conn = None
    sqlite_cursor = None
    try:
        # 1. Fetch current schema size from Oracle
        oracle_conn = get_db_connection(tns_alias)
        oracle_cursor = oracle_conn.cursor()
        oracle_cursor.execute("""
            SELECT
                SUM(NVL(bytes, 0)) / 1024 / 1024 / 1024 AS used_gb
            FROM
                dba_segments
            WHERE
                owner = :schema_name
        """, schema_name=schema_name)
        current_schema_size_row = oracle_cursor.fetchone()
        current_used_gb = current_schema_size_row[0] if current_schema_size_row and current_schema_size_row[0] else 0.0

        # 2. Log current schema usage to SQLite
        log_schema_history(tns_alias, schema_name, current_used_gb)

        # 3. Retrieve historical data from SQLite
        sqlite_conn = sqlite3.connect(HISTORY_DB_PATH)
        sqlite_cursor = sqlite_conn.cursor()

        history_query = """
            SELECT timestamp, used_gb
            FROM schema_history
            WHERE tns_alias = ? AND schema_name = ?
        """
        query_params = [tns_alias, schema_name]

        if start_date_str:
            history_query += " AND timestamp >= ?"
            query_params.append(start_date_str)
        if end_date_str:
            history_query += " AND timestamp <= ?"
            query_params.append(end_date_str)

        history_query += " ORDER BY timestamp"

        sqlite_cursor.execute(history_query, tuple(query_params))
        history_data = [{"timestamp": r[0], "used_gb": r[1]} for r in sqlite_cursor.fetchall()]

        return jsonify(history_data)
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error fetching schema history: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if oracle_cursor:
            oracle_cursor.close()
        if oracle_conn:
            oracle_conn.close()
        if sqlite_cursor:
            sqlite_cursor.close()
        if sqlite_conn:
            sqlite_conn.close()

@app.route('/api/schema_change_log', methods=['GET'])
def schema_change_log():
    """
    Retorna o log de alterações para um schema do banco de dados SQLite.
    Aceita parâmetros start_date e end_date para filtragem.
    """
    tns_alias = request.args.get('tns_alias')
    schema_name = request.args.get('name')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    if not tns_alias or not schema_name:
        return jsonify({"error": "TNS alias and schema name are required."}), 400

    sqlite_conn = None
    sqlite_cursor = None
    try:
        sqlite_conn = sqlite3.connect(HISTORY_DB_PATH)
        sqlite_cursor = sqlite_conn.cursor()

        log_query = """
            SELECT timestamp, change_type, description, changed_by
            FROM schema_change_log
            WHERE tns_alias = ? AND schema_name = ?
        """
        query_params = [tns_alias, schema_name]

        if start_date_str:
            log_query += " AND timestamp >= ?"
            query_params.append(start_date_str)
        if end_date_str:
            log_query += " AND timestamp <= ?"
            query_params.append(end_date_str)

        log_query += " ORDER BY timestamp DESC" # Order by most recent first

        sqlite_cursor.execute(log_query, tuple(query_params))
        log_data = [{"timestamp": r[0], "change_type": r[1], "description": r[2], "changed_by": r[3]} for r in sqlite_cursor.fetchall()]

        return jsonify(log_data)
    except sqlite3.Error as e:
        print(f"Erro ao buscar log de alterações do SQLite: {e}", file=sys.stderr)
        traceback.print_exc()
        return jsonify({"error": f"Database error: {e}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if sqlite_cursor:
            sqlite_cursor.close()
        if sqlite_conn:
            sqlite_conn.close()

# NOVO ENDPOINT: Histórico Combinado de Tablespace e Schema (MODIFICADO)
@app.route('/api/combined_history', methods=['GET'])
def combined_history():
    """
    Retorna o histórico individual de uso de tablespaces (%) e schemas (GB)
    para o TNS selecionado, com filtro de data.
    """
    tns_alias = request.args.get('tns_alias')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    if not tns_alias:
        return jsonify({"error": "TNS alias is required."}), 400

    sqlite_conn = None
    sqlite_cursor = None
    try:
        sqlite_conn = sqlite3.connect(HISTORY_DB_PATH)
        sqlite_cursor = sqlite_conn.cursor()

        # Query para histórico de tablespaces (individual)
        tablespace_history_query = """
            SELECT timestamp, tablespace_name, used_percent
            FROM tablespace_history
            WHERE tns_alias = ?
        """
        # Query para histórico de schemas (individual)
        schema_history_query = """
            SELECT timestamp, schema_name, used_gb
            FROM schema_history
            WHERE tns_alias = ?
        """

        # Parâmetros para a consulta de tablespaces
        ts_query_params = [tns_alias]
        if start_date_str:
            tablespace_history_query += " AND timestamp >= ?"
            ts_query_params.append(start_date_str)
        if end_date_str:
            tablespace_history_query += " AND timestamp <= ?"
            ts_query_params.append(end_date_str)
        tablespace_history_query += " ORDER BY timestamp, tablespace_name"

        # Parâmetros para a consulta de schemas
        schema_query_params = [tns_alias]
        if start_date_str:
            schema_history_query += " AND timestamp >= ?"
            schema_query_params.append(start_date_str)
        if end_date_str:
            schema_history_query += " AND timestamp <= ?"
            schema_query_params.append(end_date_str)
        schema_history_query += " ORDER BY timestamp, schema_name"

        # Fetch tablespace data
        sqlite_cursor.execute(tablespace_history_query, tuple(ts_query_params))
        tablespace_data = [{"timestamp": r[0], "name": r[1], "value": round(r[2], 2)} for r in sqlite_cursor.fetchall()]

        # Fetch schema data
        sqlite_cursor.execute(schema_history_query, tuple(schema_query_params))
        schema_data = [{"timestamp": r[0], "name": r[1], "value": round(r[2], 2)} for r in sqlite_cursor.fetchall()]

        return jsonify({
            "tablespace_individual_history": tablespace_data,
            "schema_individual_history": schema_data
        })

    except sqlite3.Error as e:
        print(f"Erro ao buscar histórico combinado do SQLite: {e}", file=sys.stderr)
        traceback.print_exc()
        return jsonify({"error": f"Database error: {e}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if sqlite_cursor:
            sqlite_cursor.close()
        if sqlite_conn:
            sqlite_conn.close()


@app.route('/api/active_sessions', methods=['GET'])
def active_sessions():
    """Retorna informações sobre sessões ativas."""
    tns_alias = request.args.get('tns_alias')
    if not tns_alias:
        return jsonify({"error": "TNS alias is required."}), 400

    if not ENABLE_ACTIVE_SESSIONS:
        return jsonify({"message": "Active sessions monitoring is disabled."}), 200

    conn = None
    cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()

        # Total Sessions
        cursor.execute("SELECT COUNT(*) FROM v$session")
        total_sessions = cursor.fetchone()[0]

        # Session Status Summary
        cursor.execute("""
            SELECT
                status,
                COUNT(*)
            FROM
                v$session
            ORDER BY
                COUNT(*) DESC
            FETCH FIRST 5 ROWS ONLY -- Adicionado limite para v$session
        """)
        status_summary = [{"status": r[0], "count": r[1]} for r in cursor]

        # Top 5 Users by Sessions
        cursor.execute("""
            SELECT
                username,
                COUNT(*) AS session_count
            FROM
                v$session
            WHERE
                username IS NOT NULL
            GROUP BY
                username
            ORDER BY
                session_count DESC
            FETCH FIRST 5 ROWS ONLY
        """)
        top_users = [{"username": r[0], "count": r[1]} for r in cursor]

        # Top 5 Programs by Sessions
        cursor.execute("""
            SELECT
                program,
                COUNT(*) AS session_count
            FROM
                v$session
            WHERE
                program IS NOT NULL
            GROUP BY
                program
            ORDER BY
                session_count DESC
            FETCH FIRST 5 ROWS ONLY
        """)
        top_programs = [{"program": r[0], "count": r[1]} for r in cursor]

        # Waiting Sessions (Top 5 Events)
        waiting_sessions = []
        if ENABLE_WAITING_SESSIONS:
            cursor.execute("""
                SELECT
                    event,
                    wait_class,
                    COUNT(*) AS session_count
                FROM
                    v$session
                WHERE
                    wait_class != 'Idle' AND status = 'ACTIVE'
                GROUP BY
                    event, wait_class
                ORDER BY
                    session_count DESC
                FETCH FIRST 5 ROWS ONLY
            """)
            waiting_sessions = [{"event": r[0], "wait_class": r[1], "count": r[2]} for r in cursor]

        # Blocked Sessions
        blocked_sessions = []
        if ENABLE_BLOCKED_SESSIONS:
            cursor.execute("""
                SELECT
                    s.sid AS blocked_sid,
                    s.username AS blocked_user,
                    s.event AS blocked_event,
                    sw.sid AS blocking_sid,
                    sw.username AS blocking_user
                FROM
                    v$session s
                JOIN
                    v$session sw ON s.blocking_session = sw.sid
                WHERE
                    s.blocking_session IS NOT NULL
                FETCH FIRST 5 ROWS ONLY -- Adicionado limite para v$session
            """)
            blocked_sessions = [{"blocked_sid": r[0], "blocked_user": r[1], "blocked_event": r[2],
                                 "blocking_sid": r[3], "blocking_user": r[4]} for r in cursor]

        return jsonify({
            "total_sessions": total_sessions,
            "status_summary": status_summary,
            "top_users": top_users,
            "top_programs": top_programs,
            "waiting_sessions": waiting_sessions,
            "blocked_sessions": blocked_sessions
        })
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error fetching active sessions: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/instance_health', methods=['GET'])
def instance_health():
    """Retorna o status de saúde da instância Oracle."""
    tns_alias = request.args.get('tns_alias')
    if not tns_alias:
        return jsonify({"error": "TNS alias is required."}), 400

    if not ENABLE_INSTANCE_HEALTH:
        return jsonify({"message": "Instance health monitoring is disabled."}), 200

    conn = None
    cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                instance_name,
                status,
                host_name,
                version,
                startup_time
            FROM
                v$instance
        """)
        row = cursor.fetchone()

        instance_info = {
            "instance_name": row[0],
            "status": row[1],
            "host_name": row[2],
            "version": row[3],
            "startup_time": row[4].strftime('%Y-%m-%d %H:%M:%S') if row[4] else 'N/A',
            "connected_tns": tns_alias # Add the connected TNS for display
        }
        return jsonify(instance_info)
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error fetching instance health: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/app_version', methods=['GET'])
def app_version():
    """Retorna a versão da aplicação."""
    return jsonify({"version": APP_VERSION})

@app.route('/api/change_schema_password', methods=['POST'])
def change_schema_password():
    """Altera a palavra-passe de um schema."""
    tns_alias = request.json.get('tns_alias')
    schema_name = request.json.get('schema_name')
    new_password = request.json.get('new_password')
    admin_password = request.json.get('admin_password')

    if admin_password != ADMIN_PASSWORD:
        return jsonify({"error": "Senha administrativa incorreta."}), 403

    if not all([tns_alias, schema_name, new_password]):
        return jsonify({"error": "TNS alias, schema name e nova palavra-passe são necessários."}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()
        # Enclose schema_name in double quotes to handle case-sensitive or special character names
        sql = f"ALTER USER \"{schema_name}\" IDENTIFIED BY \"{new_password}\""
        print(f"Executing SQL: {sql}") # Log the SQL for debugging
        cursor.execute(sql)
        conn.commit()
        add_change_log_entry(tns_alias, schema_name, "PASSWORD_CHANGE", f"Palavra-passe alterada para o schema '{schema_name}'.")
        return jsonify({"message": "Palavra-passe alterada com sucesso."}), 200
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error changing schema password: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# NOVO ENDPOINT: Alterar Tablespace Padrão do Schema
@app.route('/api/change_default_tablespace', methods=['POST'])
def change_default_tablespace():
    """Altera o tablespace padrão de um schema."""
    tns_alias = request.json.get('tns_alias')
    schema_name = request.json.get('schema_name')
    new_default_tablespace = request.json.get('new_default_tablespace')
    admin_password = request.json.get('admin_password')

    if admin_password != ADMIN_PASSWORD:
        return jsonify({"error": "Senha administrativa incorreta."}), 403

    if not all([tns_alias, schema_name, new_default_tablespace]):
        return jsonify({"error": "TNS alias, nome do schema e novo tablespace padrão são necessários."}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()

        # Verifica se o tablespace existe
        cursor.execute("SELECT tablespace_name FROM dba_tablespaces WHERE tablespace_name = :ts_name", ts_name=new_default_tablespace.upper())
        if not cursor.fetchone():
            return jsonify({"error": f"Tablespace '{new_default_tablespace}' não existe."}), 400

        # Enclose schema_name in double quotes to handle case-sensitive or special character names
        sql = f"ALTER USER \"{schema_name}\" DEFAULT TABLESPACE {new_default_tablespace}"
        print(f"Executing SQL: {sql}") # Log the SQL for debugging
        cursor.execute(sql)
        conn.commit()
        add_change_log_entry(tns_alias, schema_name, "DEFAULT_TABLESPACE_CHANGE", f"Tablespace padrão alterado para '{new_default_tablespace}' para o schema '{schema_name}'.")
        return jsonify({"message": "Tablespace padrão alterado com sucesso."}), 200
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error changing default tablespace: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/drop_schema', methods=['POST'])
def drop_schema():
    """Remove um schema do banco de dados."""
    tns_alias = request.json.get('tns_alias')
    schema_name = request.json.get('schema_name')
    admin_password = request.json.get('admin_password')

    if admin_password != ADMIN_PASSWORD:
        return jsonify({"error": "Senha administrativa incorreta."}), 403

    if not all([tns_alias, schema_name]):
        return jsonify({"error": "TNS alias e nome do schema são necessários."}), 400

    # Iniciar a operação de drop em uma thread separada
    # e armazenar seu status em SCHEMA_DROP_STATUS
    SCHEMA_DROP_STATUS[schema_name] = {'status': 'IN_PROGRESS', 'message': 'Iniciando drop...'}

    # Usar threading para não bloquear a requisição HTTP
    drop_thread = threading.Thread(target=execute_drop_schema, args=(tns_alias, schema_name))
    drop_thread.start()

    return jsonify({"message": f"Operação de drop para o schema '{schema_name}' iniciada em segundo plano."}), 202

def execute_drop_schema(tns_alias, schema_name):
    """Função executada em thread separada para dropar o schema."""
    conn = None
    cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()
        # CASCADE para dropar objetos do schema também
        # Enclose schema_name in double quotes
        sql = f"DROP USER \"{schema_name}\" CASCADE"
        print(f"Executing async SQL (DROP USER): {sql}", file=sys.stderr)
        cursor.execute(sql)
        conn.commit()
        add_change_log_entry(tns_alias, schema_name, "USER_DROP", f"Usuário '{schema_name}' dropado.")
        SCHEMA_DROP_STATUS[schema_name] = {'status': 'COMPLETED', 'message': 'Drop concluído com sucesso.'}
        print(f"Async drop of schema '{schema_name}' completed successfully.", file=sys.stderr)
    except cx_Oracle.Error as e:
        error_obj, = e.args
        error_message = f"Oracle Error dropping schema: {error_obj.message}"
        print(error_message, file=sys.stderr)
        traceback.print_exc()
        SCHEMA_DROP_STATUS[schema_name] = {'status': 'FAILED', 'message': error_message}
    except Exception as e:
        error_message = f"An unexpected error occurred during schema drop: {str(e)}"
        print(error_message, file=sys.stderr)
        traceback.print_exc()
        SCHEMA_DROP_STATUS[schema_name] = {'status': 'FAILED', 'message': error_message}
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
        # Limpar o status após um tempo para evitar que o dicionário cresça indefinidamente
        # Isso pode ser ajustado para um mecanismo de limpeza mais sofisticado em produção
        time.sleep(60) # Manter o status por 60 segundos para o frontend buscar
        if schema_name in SCHEMA_DROP_STATUS and SCHEMA_DROP_STATUS[schema_name]['status'] != 'IN_PROGRESS':
            del SCHEMA_DROP_STATUS[schema_name]
            print(f"Status de drop para '{schema_name}' limpo após conclusão/falha.", file=sys.stderr)

@app.route('/api/schema_drop_status', methods=['GET'])
def schema_drop_status():
    """Retorna o status de uma operação de drop de schema."""
    schema_name = request.args.get('schema_name')
    if not schema_name:
        return jsonify({"error": "Schema name is required."}), 400

    status = SCHEMA_DROP_STATUS.get(schema_name, {'status': 'NOT_FOUND', 'message': 'Operação não encontrada ou concluída.'})
    return jsonify(status)

@app.route('/api/lock_schema', methods=['POST'])
def lock_schema():
    """Bloqueia um schema no banco de dados."""
    tns_alias = request.json.get('tns_alias')
    schema_name = request.json.get('schema_name')
    admin_password = request.json.get('admin_password')

    if admin_password != ADMIN_PASSWORD:
        return jsonify({"error": "Senha administrativa incorreta."}), 403

    if not all([tns_alias, schema_name]):
        return jsonify({"error": "TNS alias e nome do schema são necessários."}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()
        # Enclose schema_name in double quotes
        sql = f"ALTER USER \"{schema_name}\" ACCOUNT LOCK"
        print(f"Executing SQL: {sql}") # Log the SQL for debugging
        cursor.execute(sql)
        conn.commit()
        add_change_log_entry(tns_alias, schema_name, "ACCOUNT_LOCK", f"Conta do usuário '{schema_name}' bloqueada.")
        return jsonify({"message": f"Usuário {schema_name} bloqueado com sucesso."}), 200
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error locking schema: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/unlock_schema', methods=['POST'])
def unlock_schema():
    """Desbloqueia um schema no banco de dados."""
    tns_alias = request.json.get('tns_alias')
    schema_name = request.json.get('schema_name')
    admin_password = request.json.get('admin_password')

    if admin_password != ADMIN_PASSWORD:
        return jsonify({"error": "Senha administrativa incorreta."}), 403

    if not all([tns_alias, schema_name]):
        return jsonify({"error": "TNS alias e nome do schema são necessários."}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()
        # Enclose schema_name in double quotes
        sql = f"ALTER USER \"{schema_name}\" ACCOUNT UNLOCK"
        print(f"Executing SQL: {sql}") # Log the SQL for debugging
        cursor.execute(sql)
        conn.commit()
        add_change_log_entry(tns_alias, schema_name, "ACCOUNT_UNLOCK", f"Conta do usuário '{schema_name}' desbloqueada.")
        return jsonify({"message": f"Usuário {schema_name} desbloqueado com sucesso."}), 200
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error unlocking schema: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/add_schema_grant', methods=['POST'])
def add_schema_grant():
    """Concede um privilégio ou role a um schema."""
    tns_alias = request.json.get('tns_alias')
    schema_name = request.json.get('schema_name')
    grant_name = request.json.get('grant_name')
    with_admin_option = request.json.get('with_admin_option', False)
    admin_password = request.json.get('admin_password')

    if admin_password != ADMIN_PASSWORD:
        return jsonify({"error": "Senha administrativa incorreta."}), 403

    if not all([tns_alias, schema_name, grant_name]):
        return jsonify({"error": "TNS alias, nome do schema e nome do grant são necessários."}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()

        admin_option_clause = " WITH ADMIN OPTION" if with_admin_option else ""
        # Enclose schema_name in double quotes
        sql = f"GRANT {grant_name} TO \"{schema_name}\"{admin_option_clause}"
        print(f"Executing SQL: {sql}") # Log the SQL for debugging
        cursor.execute(sql)
        conn.commit()
        add_change_log_entry(tns_alias, schema_name, "GRANT_ADD", f"Grant '{grant_name}' concedido ao schema '{schema_name}'.")
        return jsonify({"message": "Grant adicionado com sucesso."}), 200
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error adding schema grant: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/create_user', methods=['POST'])
def create_user():
    """Cria um novo utilizador (schema) no banco de dados."""
    tns_alias = request.json.get('tns_alias')
    username = request.json.get('username')
    password = request.json.get('password')
    default_tablespace = request.json.get('default_tablespace')
    temporary_tablespace = request.json.get('temporary_tablespace')
    grant_dba = request.json.get('grant_dba', False)
    grant_create_session = request.json.get('grant_create_session', False)
    admin_password = request.json.get('admin_password')

    if admin_password != ADMIN_PASSWORD:
        return jsonify({"error": "Senha administrativa incorreta."}), 403

    if not all([tns_alias, username, password, default_tablespace]):
        return jsonify({"error": "TNS alias, nome de utilizador, palavra-passe e tablespace padrão são necessários."}), 400

    if not grant_dba and not grant_create_session:
        return jsonify({"error": "O utilizador deve ter pelo menos o privilégio CREATE SESSION ou DBA."}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()

        # Create user
        # Enclose username in double quotes
        sql_create_user = f"CREATE USER \"{username}\" IDENTIFIED BY \"{password}\" DEFAULT TABLESPACE {default_tablespace}"
        if temporary_tablespace:
            sql_create_user += f" TEMPORARY TABLESPACE {temporary_tablespace}"
        print(f"Executing SQL: {sql_create_user}")
        cursor.execute(sql_create_user)

        # Grant privileges
        if grant_create_session:
            sql_grant_session = f"GRANT CREATE SESSION TO \"{username}\""
            print(f"Executing SQL: {sql_grant_session}")
            cursor.execute(sql_grant_session)
        if grant_dba:
            sql_grant_dba = f"GRANT DBA TO \"{username}\""
            print(f"Executing SQL: {sql_grant_dba}")
            cursor.execute(sql_grant_dba)

        conn.commit()
        add_change_log_entry(tns_alias, username, "USER_CREATE", f"Usuário '{username}' criado.")
        return jsonify({"message": "Utilizador criado com sucesso."}), 200
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error creating user: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/validate_admin_password', methods=['POST'])
def validate_admin_password():
    """Valida a senha administrativa."""
    admin_password_input = request.json.get('admin_password')
    if admin_password_input == ADMIN_PASSWORD:
        return jsonify({"success": True, "message": "Senha validada."}), 200
    else:
        return jsonify({"success": False, "error": "Senha administrativa incorreta."}), 403

# NOVO ENDPOINT: Obter diretórios Datapump
@app.route('/api/datapump_directories', methods=['GET'])
def datapump_directories():
    """Retorna uma lista de diretórios Datapump configurados no Oracle."""
    tns_alias = request.args.get('tns_alias')
    if not tns_alias:
        return jsonify({"error": "TNS alias is required."}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection(tns_alias)
        cursor = conn.cursor()
        cursor.execute("SELECT directory_name FROM dba_directories ORDER BY directory_name")
        directories = [row[0] for row in cursor.fetchall()]
        return jsonify(directories), 200
    except cx_Oracle.Error as e:
        error_obj, = e.args
        print(f"Oracle Error fetching datapump directories: {error_obj.message}")
        traceback.print_exc()
        return jsonify({"error": f"Database error: {error_obj.message}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def run_datapump_backup(tns_alias, schema_name, directory, dmp_file, log_file):
    """
    Executa um backup Datapump real usando subprocess.
    Requer que o ambiente Oracle (ORACLE_HOME, LD_LIBRARY_PATH/PATH) esteja configurado
    corretamente para o usuário que executa o Flask.
    """
    db_config = DB_CONFIGS.get(tns_alias)
    if not db_config:
        error_message = f"Configuração para TNS alias '{tns_alias}' não encontrada para backup."
        print(error_message, file=sys.stderr)
        add_change_log_entry(tns_alias, schema_name, "BACKUP_FAILED", error_message, changed_by="System")
        backup_statuses[schema_name] = {"status": "falhou", "log_output": [error_message]}
        return

    # Construir a string de conexão para expdp
    # É mais seguro usar um arquivo de parâmetros ou variáveis de ambiente para senhas em produção.
    # Para homologação, esta abordagem direta pode ser aceitável com os devidos cuidados.
    connect_string = f"{db_config['user']}/{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['service_name']}"

    # Construir o comando expdp
    command = [
        'expdp',
        connect_string,
        f'SCHEMAS={schema_name}',
        f'DIRECTORY={directory}',
        f'DUMPFILE={dmp_file}',
        f'LOGFILE={log_file}'
    ]

    print(f"Iniciando backup REAL para o schema: {schema_name}", file=sys.stderr)
    print(f"Comando expdp: {' '.join(command)}", file=sys.stderr) # Cuidado ao logar senhas em produção!

    add_change_log_entry(tns_alias, schema_name, "BACKUP_START", f"Backup Datapump iniciado para o schema '{schema_name}'. Arquivo DMP: {dmp_file}", changed_by="System")

    backup_statuses[schema_name] = {
        "status": "backup em andamento",
        "log_output": [] # Inicializa o log de saída
    }

    process = None
    try:
        # Usar Popen para executar o comando em segundo plano
        # stdout e stderr são redirecionados para PIPE para que possamos lê-los
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)

        # Monitorar a saída em tempo real e atualizar o status
        while True:
            # Tenta ler uma linha do stdout ou stderr sem bloquear
            output_line = process.stdout.readline()
            error_line = process.stderr.readline()

            if output_line:
                backup_statuses[schema_name]['log_output'].append(output_line.strip())
                print(f"expdp stdout: {output_line.strip()}", file=sys.stderr)
            if error_line:
                backup_statuses[schema_name]['log_output'].append(f"ERROR: {error_line.strip()}")
                print(f"expdp stderr: {error_line.strip()}", file=sys.stderr)

            # Verifica se o processo terminou
            return_code = process.poll()
            if return_code is not None:
                # Processo terminou, lê qualquer output restante
                for line in process.stdout.readlines():
                    backup_statuses[schema_name]['log_output'].append(line.strip())
                    print(f"expdp stdout (final): {line.strip()}", file=sys.stderr)
                for line in process.stderr.readlines():
                    backup_statuses[schema_name]['log_output'].append(f"ERROR: {line.strip()}")
                    print(f"expdp stderr (final): {line.strip()}", file=sys.stderr)
                break
            
            time.sleep(0.5) # Pequena pausa para não sobrecarregar a CPU e permitir que o expdp escreva.

        if process.returncode == 0:
            backup_statuses[schema_name].update({
                "status": "concluído",
                "end_time": datetime.datetime.now().isoformat()
            })
            print(f"Backup REAL para o schema {schema_name} concluído com sucesso!", file=sys.stderr)
            add_change_log_entry(tns_alias, schema_name, "BACKUP_COMPLETED", f"Backup Datapump concluído com sucesso para o schema '{schema_name}'. Arquivo DMP: {dmp_file}", changed_by="System")
        else:
            error_message = f"expdp falhou com código {process.returncode}. Verifique o log para detalhes."
            backup_statuses[schema_name].update({
                "status": "falhou",
                "end_time": datetime.datetime.now().isoformat(),
                "error_message": error_message
            })
            print(f"Backup REAL para o schema {schema_name} FALHOU! Erro: {error_message}", file=sys.stderr)
            add_change_log_entry(tns_alias, schema_name, "BACKUP_FAILED", f"Backup Datapump falhou para o schema '{schema_name}': {error_message}", changed_by="System")

    except FileNotFoundError:
        error_message = "Comando 'expdp' não encontrado. Verifique se o cliente Oracle está instalado e no PATH do servidor."
        print(error_message, file=sys.stderr)
        backup_statuses[schema_name].update({
            "status": "falhou",
            "end_time": datetime.datetime.now().isoformat(),
            "error_message": error_message,
            "log_output": backup_statuses[schema_name]['log_output'] + [error_message]
        })
        add_change_log_entry(tns_alias, schema_name, "BACKUP_FAILED", f"Backup Datapump falhou para o schema '{schema_name}': {error_message}", changed_by="System")
    except Exception as e:
        error_message = f"Um erro inesperado ocorreu durante o backup para {schema_name}: {str(e)}"
        print(error_message, file=sys.stderr)
        backup_statuses[schema_name].update({
            "status": "falhou",
            "end_time": datetime.datetime.now().isoformat(),
            "error_message": error_message,
            "log_output": backup_statuses[schema_name]['log_output'] + [error_message]
        })
        add_change_log_entry(tns_alias, schema_name, "BACKUP_FAILED", f"Backup Datapump falhou para o schema '{schema_name}': {str(e)}", changed_by="System")
    finally:
        if process and process.poll() is None: # Se o processo ainda estiver a correr
            process.terminate() # Tenta terminar o processo
            print(f"Processo expdp para '{schema_name}' terminado.", file=sys.stderr)
        # Não limpar o status aqui, o frontend será responsável por parar o polling
        # e o status permanecerá no dicionário até que a aplicação Flask seja reiniciada.


# Nova API endpoint para iniciar o backup
@app.route('/api/initiate_backup', methods=['POST'])
def initiate_backup():
    """
    Recebe os detalhes do backup e inicia o processo em uma thread separada.
    """
    data = request.get_json()
    tns_alias = data.get('tns_alias')
    schema_name = data.get('schema_name')
    directory = data.get('directory')
    dmp_file = data.get('dmp_file')
    log_file = data.get('log_file')
    admin_password = data.get('admin_password')

    if admin_password != ADMIN_PASSWORD:
        return jsonify({"success": False, "message": "Senha administrativa incorreta."}), 403

    if not all([tns_alias, schema_name, directory, dmp_file, log_file]):
        return jsonify({"success": False, "message": "Dados de backup incompletos (TNS alias, schema, diretório, arquivos DMP/LOG são necessários).", "data_received": data}), 400

    if backup_statuses.get(schema_name, {}).get("status") in ["backup em andamento", "iniciando backup"]:
        return jsonify({"success": False, "message": "Backup já em andamento para este schema."}), 409

    # Pass the retrieved tns_alias to the backup function
    backup_thread = threading.Thread(target=run_datapump_backup, args=(tns_alias, schema_name, directory, dmp_file, log_file))
    backup_thread.start()

    # Atualiza o status inicial imediatamente
    backup_statuses[schema_name] = {
        "status": "iniciando backup",
        "log_output": ["Iniciando operação de backup..."]
    }

    return jsonify({"success": True, "message": f"Backup para {schema_name} iniciado com sucesso!"})


# Nova API endpoint para verificar o status do backup
@app.route('/api/backup_status/<schema_name>', methods=['GET'])
def get_backup_status(schema_name):
    """
    Retorna o status atual do backup para um dado schema.
    """
    status = backup_statuses.get(schema_name, {
        "status": "nenhum backup",
        "log_output": []
    })
    return jsonify(status)


if __name__ == '__main__':
    try:
        load_db_config()
        init_history_db() # Initialize SQLite database on app startup
        # Conditional SSL context for app.run
        if SSL_ENABLED:
            if not os.path.exists(SSL_CERT_PATH) or not os.path.exists(SSL_KEY_PATH):
                raise FileNotFoundError(f"Certificado SSL '{SSL_CERT_PATH}' ou chave '{SSL_KEY_PATH}' não encontrados. Por favor, verifique os caminhos no config.ini ou gere-os.")
            print(f"A iniciar a aplicação Flask com SSL em https://0.0.0.0:5000/ (Versão {APP_VERSION})", file=sys.stderr)
            app.run(debug=True, host='0.0.0.0', port=5000, ssl_context=(SSL_CERT_PATH, SSL_KEY_PATH))
        else:
            print(f"A iniciar a aplicação Flask sem SSL em http://0.0.0.0:5000/ (Versão {APP_VERSION})", file=sys.stderr)
            app.run(debug=True, host='0.0.0.0', port=5000)

    except (RuntimeError, configparser.Error, KeyError, FileNotFoundError, ValueError) as e:
        print(f"\nERRO CRÍTICO NA INICIALIZAÇÃO: {e}", file=sys.stderr)
        print("Certifique-se de que 'config.ini' existe na mesma pasta de 'app.py'", file=sys.stderr)
        print("e que contém seções [tns:seu_alias] com 'user', 'password', 'host', 'port', 'service_name'.", file=sys.stderr)
        print("e, opcionalmente, a secção [ui_features] e [ssl_config].", file=sys.stderr)
        print("Certifique-se também de que a senha administrativa está definida na seção [admin_security].", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nUm erro inesperado ocorreu durante a inicialização: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
