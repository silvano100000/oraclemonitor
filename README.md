Estrutura:
- app.py
- config.ini
- history.db
- templates
--index.html
- static
--my_style.css


Documentação de Instalação da Aplicação Oracle Monitor

Este documento detalha os passos necessários para instalar e configurar a aplicação de monitoramento Oracle. A aplicação consiste em um backend Flask (Python) e um frontend web (HTML, CSS, JavaScript).

Pré-requisitos

Para que a aplicação funcione corretamente, você precisará ter os seguintes softwares instalados e configurados no servidor onde a aplicação será executada:

    Python 3.x: (Recomendado Python 3.8 ou superior)

        Verifique a instalação com: python3 --version

    pip: Gerenciador de pacotes do Python.

        Geralmente, vem com o Python 3.x. Verifique com: pip3 --version

    Oracle Instant Client: É necessário para a conexão do Python com o banco de dados Oracle via cx_Oracle.

        Baixe a versão "Basic" ou "Basic Light" e a versão "SDK" compatíveis com seu sistema operacional e versão do Oracle Database.

        Configuração do Ambiente:

            Linux/macOS: Descompacte os arquivos e defina a variável de ambiente LD_LIBRARY_PATH (Linux) ou DYLD_LIBRARY_PATH (macOS) para o diretório onde o Instant Client foi descompactado. Adicione também o diretório do Instant Client ao PATH.
            Bash

            export LD_LIBRARY_PATH=/path/to/instantclient_xx_x:$LD_LIBRARY_PATH
            export PATH=/path/to/instantclient_xx_x:$PATH

            (Substitua xx_x pela sua versão e /path/to/instantclient_xx_x pelo caminho real)

            Windows: Descompacte o Instant Client e adicione o caminho do diretório ao PATH do sistema.

        Comando expdp: Para o funcionamento do recurso de backup Data Pump, o executável expdp precisa estar acessível no PATH do sistema do usuário que executa a aplicação Flask. Isso geralmente é garantido se você tiver um Oracle Client completo ou o Instant Client com os utilitários de Data Pump configurados corretamente.

    Acesso ao Banco de Dados Oracle:

        Credenciais de um usuário Oracle com privilégios de SELECT nas views V$INSTANCE, DBA_DATA_FILES, DBA_FREE_SPACE, DBA_TABLESPACES, DBA_USERS, DBA_ROLE_PRIVS, DBA_SYS_PRIVS, DBA_TAB_PRIVS, DBA_SEGMENTS, DBA_OBJECTS, e DBA_DIRECTORIES.

        Para as operações de "Dropar Usuário", "Bloquear/Desbloquear Usuário", "Alterar Senha do Schema", "Adicionar Grant" e "Criar Usuário" e "Backup Datapump", o usuário configurado no config.ini precisa ter privilégios administrativos (ex: DBA ou SYSDBA ou privilégios granulares suficientes para ALTER USER, DROP USER, GRANT, e para a execução de Data Pump).

Passos de Instalação

Siga estes passos para instalar e preparar a aplicação:

1. Obter os Arquivos da Aplicação

Certifique-se de que todos os arquivos da aplicação ( app.py, config.ini, index.html, my_style.css) estejam no mesmo diretório no seu servidor.

2. Criar um Ambiente Virtual (Recomendado porem "opcional") 

É uma boa prática usar um ambiente virtual para isolar as dependências do projeto.
Bash

python3 -m venv venv

3. Ativar o Ambiente Virtual

    Linux/macOS:
    Bash

source venv/bin/activate

Windows:
Bash

    .\venv\Scripts\activate

4. Instalar as Dependências Python

Com o ambiente virtual ativado, instale as bibliotecas Python necessárias:
Bash

pip install Flask Flask-Cors cx_Oracle configparser

    Observação: Se encontrar problemas com cx_Oracle (principalmente no Windows), verifique se o Oracle Instant Client está corretamente instalado e configurado no PATH do sistema.

5. Configurar o Arquivo config.ini

O arquivo config.ini é crucial para a conexão com o banco de dados e outras configurações da aplicação.

Abra config.ini em um editor de texto e ajuste as seguintes seções:

    [tns:SEU_ALIAS]: Configure os detalhes de conexão para cada instância Oracle que deseja monitorar. Você pode adicionar múltiplas seções [tns:ALIAS_DO_SEU_BANCO].

        user: Nome de usuário do Oracle (ex: SYSTEM).

        password: Senha do usuário.

        host: Endereço IP ou hostname do servidor Oracle.

        port: Porta do listener Oracle (padrão é 1521).

        service_name: Nome do serviço do banco de dados (ex: ORCLPDB1, XE).

        excluded_tablespaces: Lista de tablespaces a serem excluídos da visualização (separados por vírgula).

        excluded_schemas: Lista de schemas a serem excluídos da visualização (separados por vírgula).

        tablespace_warning_percent: Limite de porcentagem para alerta de WARNING de tablespace.

        tablespace_critical_percent: Limite de porcentagem para alerta de CRITICAL de tablespace.

        schema_warning_gb: Limite em GB para alerta de WARNING de schema.

        schema_critical_gb: Limite em GB para alerta de CRITICAL de schema.

    [ui_features]: Habilite ou desabilite seções específicas da interface do usuário. Use yes ou no.

        enable_active_sessions: Habilita o monitoramento de sessões ativas.

        enable_instance_health: Habilita o monitoramento da saúde da instância.

        enable_session_status_box, enable_top_users_box, etc.: Controlam caixas de informações específicas dentro da seção de sessões ativas.

    [ssl_config]: Configure o SSL para a aplicação Flask.

        ssl_enabled: Defina como yes para habilitar SSL.

        ssl_cert_path: Caminho para o arquivo do certificado SSL (ex: cert.pem).

        ssl_key_path: Caminho para o arquivo da chave privada SSL (ex: key.pem).

        Se ssl_enabled = yes, você precisará gerar ou obter esses arquivos. Para testes, você pode gerar certificados autoassinados:
        Bash

        openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

        (Siga as instruções para preencher os detalhes. O Common Name deve ser o IP ou hostname do servidor.)

    [admin_security]: Defina a senha administrativa para operações sensíveis.

        admin_password: Mude admin para uma senha forte e segura.

    [email_notifications]: (Atualmente enable = no no config.ini fornecido)

        Se desejar habilitar notificações por e-mail no futuro, preencha estas informações.

    [history_db]: Define o caminho para o arquivo do banco de dados SQLite.

        db_path: Mantenha como history.db para que seja criado no mesmo diretório da aplicação, ou defina um caminho absoluto (ex: C:\MonitorOracle\history.db ou /opt/monitor_oracle/history.db).

6. Inicializar o Banco de Dados SQLite

Na primeira execução, a aplicação irá criar o arquivo history.db e as tabelas necessárias (schema_history, tablespace_history, schema_change_log, backup_jobs).

Se você mudar o db_path no config.ini, certifique-se de que o diretório especificado exista e que o usuário que executa a aplicação tenha permissões de leitura e escrita.

7. Iniciar a Aplicação Flask

Com o ambiente virtual ativado e o config.ini configurado, você pode iniciar a aplicação:
