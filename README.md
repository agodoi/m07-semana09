# Prevenção Contra SQL Injection

Neste encontro iremos abordar a proteção de dados na nuvem no contexto de desenvolvimento de aplicações seguras e proteção contra ataques de SQL Injection.

# Vantagens para o seu Projeto

Entender os riscos de SQL Injection no projeto da Vivo minimiza as vulnerabilidades, já que o SQL Injection é dos ataques mais famosos que visa explorar falhas de segurança em aplicações que interagem com bancos de dados, permitindo que invasores insiram ou manipulem consultas SQL maliciosas.

Dependendo da forma que você interage com as aplicações de RDS do seu projeto, o invasor pode apagar seu banco em alguns segundos.

### 1. Proteção de Dados Sensíveis
   - O sistema de inventário descrito lida com a sincronização de dados de estoque de vários centros de distribuição e lojas. Proteger o banco de dados contra SQL Injection garante que informações críticas, como quantidades de estoque e detalhes de centros de distribuição, sejam mantidas seguras, impedindo o vazamento de dados internos que poderiam prejudicar a operação.

### 2. Maior Confiabilidade do Sistema
   - Ao implementar mecanismos que evitam SQL Injection, como prepared statements ou ORM (Object-Relational Mapping), a confiabilidade do sistema aumenta, pois ele não será vulnerável a manipulações externas. Isso é crucial para garantir que o sistema de inventário distribuído continue funcionando corretamente, sem interferências de usuários maliciosos.

### 3. Preservação da Integridade dos Dados
   - Prevenir SQL Injection assegura que os dados no banco permaneçam íntegros. Isso é essencial para o correto funcionamento do sistema de inventário, onde dados de estoque devem ser sincronizados em tempo real. A integridade dos dados é fundamental para evitar discrepâncias no inventário, o que pode resultar em falhas na entrega e no gerenciamento logístico.

### 4. Conformidade com Normas de Segurança
   - Empresas como a Vivo estão frequentemente sujeitas a regulamentações de privacidade e segurança de dados (como LGPD). A prevenção de ataques de SQL Injection é uma prática de segurança recomendada que ajuda a empresa a se manter em conformidade com essas normas, evitando multas e danos à reputação.

### 5. Redução de Custos com Incidentes de Segurança
   - Investir na prevenção de ataques como o SQL Injection pode evitar incidentes de segurança caros, tanto em termos de reparo de sistemas quanto em possíveis responsabilidades legais. Isso é especialmente importante para um sistema que opera em múltiplas localidades e lida com grandes volumes de transações, como o sistema de inventário distribuído descrito.

### 6. Melhoria na Experiência do Usuário Final
   - Um sistema que sofre menos com falhas de segurança e funciona de forma eficiente oferece uma melhor experiência para o usuário final. No caso do e-commerce B2B e B2C, evitar SQL Injection garante que os clientes possam confiar na plataforma e na exatidão dos prazos de entrega e disponibilidade de produtos.

### 7. Preparação para Escalabilidade
   - O sistema descrito precisa suportar grandes volumes de transações. Implementar medidas de segurança contra SQL Injection permite que a plataforma escale de forma segura, sem se tornar mais vulnerável à medida que o volume de usuários e transações cresce.


# Como o ataque funciona?

## Passo-01: 

Um atacante insere código SQL malicioso em um campo de entrada de um site ou aplicação.

## Passo-02:

Esse código é então executado pelo banco de dados, podendo alterar sua operação original. 

## Passo-03: Exemplos de ações possíveis

* Recuperação de dados sensíveis;

* Deleção de tabelas,

* Elevação de privilégios no sistema.


# Exemplo básico de SQL Injection

   Suponha que a aplicação tenha o seguinte código para verificar usuários:
   
   ```
   SELECT * FROM users WHERE username = '$username' AND password = '$password';
   ```
   
   Se o atacante insere no campo de senha:
   
   ```
   ' OR '1'='1
   ```
   A consulta SQL se torna:
   
   ```
   SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1';
   ```

   Isso retorna verdadeiro para todos os usuários, permitindo acesso não autorizado.

---

### 2. Consequências de um SQL Injection
   - Roubo de dados confidenciais: Informações de clientes, números de cartões de crédito.
   - Danos financeiros e de reputação: Para empresas, esses ataques podem levar a perdas financeiras, violação de normas de privacidade (como GDPR) e destruição da confiança dos clientes.
   - Controle completo do banco de dados: Em casos graves, o atacante pode obter controle total do banco, modificar ou deletar dados.

---

### 3. Prevenção de SQL Injection usando AWS

#### 3.1. Validação de Entrada
   - Filtragem e Sanitização: Certifique-se de que todas as entradas sejam validadas e filtradas para eliminar comandos SQL maliciosos. Nunca confie em dados vindos do usuário.
   
   Exemplo de Código Segurizado (Usando Prepared Statements com PHP e MySQL):
   ```php
   $stmt = $mysqli->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
   $stmt->bind_param("ss", $username, $password);
   $stmt->execute();
   $result = $stmt->get_result();
   ```
   *Usar prepared statements impede que o atacante insira código SQL diretamente na consulta.*

---

#### 3.2. Serviços da AWS para Prevenção de SQL Injection

##### 3.2.1. AWS WAF (Web Application Firewall)
   - Função: O AWS WAF ajuda a proteger suas aplicações web contra explorações comuns, incluindo SQL Injection.
   - Como configurar para SQL Injection:
     - No AWS WAF, crie regras personalizadas que bloqueiam ou limitam tentativas de SQL Injection.
     - Habilite a regra "SQL Injection Match Condition", que detecta padrões comuns de injeções de SQL nas requisições.

     Exemplo de configuração:
     - Adicione uma regra de SQL Injection à ACL do AWS WAF.
     - Associe essa ACL à distribuição do Amazon CloudFront ou ao API Gateway.

---

##### 3.2.2. Amazon RDS (Relational Database Service)
   - Função: Gerenciamento seguro de bancos de dados, com encriptação automática de dados e proteção contra falhas de segurança comuns.
   - Configurações para melhorar a segurança:
     - IAM Authentication: Use autenticação baseada no IAM para evitar senhas SQL hardcoded.
     - Encrypted connections: Garanta que as conexões com o banco sejam feitas via SSL para impedir interceptações.
     - Auditoria de Logs: Ative logs de auditoria para monitorar e registrar consultas suspeitas.

---

##### 3.2.3. Amazon Cognito
   - Função: Gerenciamento de autenticação de usuários com foco na segurança.
   - Como ajuda a prevenir SQL Injection:
     - Cognito permite que sua aplicação autentique usuários sem precisar manipular diretamente as senhas no código-fonte. Isso reduz o risco de injeções maliciosas em campos sensíveis.
     - Integre a autenticação com Cognito para criar uma camada extra de segurança.

---

##### 3.2.4. AWS Secrets Manager
   - Função: Protege segredos necessários pela aplicação (como senhas de banco de dados) e faz a rotação automática.
   - Como utilizar:
     - Configure o AWS Secrets Manager para gerenciar credenciais do banco de dados.
     - Garanta que as credenciais não estejam hardcoded no código, eliminando vetores de ataque comuns.

     Exemplo de Integração:
     ```php
     $secret = SecretsManagerClient::getSecretValue(['SecretId' => 'dbCredentials']);
     $dbConnection = new PDO("mysql:host=$secret->host;dbname=$secret->dbname", $secret->username, $secret->password);
     ```

---

### 4. Outras Boas Práticas de Segurança na AWS
   - Least Privilege Principle (Princípio do Menor Privilégio): Assegure-se de que os usuários e aplicações tenham apenas as permissões necessárias. Evite dar privilégios administrativos sem necessidade.
   - Multi-Factor Authentication (MFA): Habilite MFA para usuários IAM para aumentar a segurança das credenciais.
   - Security Groups & NACLs: Limite o acesso ao banco de dados usando regras de Security Groups e Network ACLs, permitindo apenas o tráfego necessário.
   - Monitoramento com CloudWatch e GuardDuty: Monitore atividades incomuns e potencialmente maliciosas em suas aplicações e infraestrutura, incluindo tentativas de SQL Injection.

---

### 5. Conclusão
   A prevenção de SQL Injection é uma parte crucial da segurança de qualquer aplicação web. Utilizando as ferramentas da AWS, como WAF, RDS, Secrets Manager e Cognito, é possível mitigar e proteger a aplicação contra essas ameaças. Além disso, é essencial adotar boas práticas de codificação e validação de entrada para reduzir as superfícies de ataque.

---

### 6. Exercício Prático
   1. Desafio: Crie uma aplicação simples que conecte a um banco de dados RDS na AWS. Simule uma vulnerabilidade de SQL Injection e depois aplique as técnicas de mitigação usando AWS WAF e prepared statements.
   2. Objetivo: O estudante deve demonstrar como a aplicação vulnerável pode ser atacada e, em seguida, corrigir a vulnerabilidade implementando medidas de segurança.

---

Com essa estrutura de aula, você pode explorar SQL Injection em profundidade, focando tanto nos aspectos teóricos quanto nas práticas de defesa disponíveis na AWS.
