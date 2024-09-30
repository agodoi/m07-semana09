# Prevenção Contra SQL Injection

Neste encontro iremos abordar a proteção de dados na nuvem no contexto de desenvolvimento de aplicações seguras e proteção contra ataques de SQL Injection.

## 1) Vantagens para o seu Projeto

Entender os riscos de SQL Injection no projeto da Vivo minimiza as vulnerabilidades, já que o SQL Injection é dos ataques mais famosos que visa explorar falhas de segurança em aplicações que interagem com bancos de dados, permitindo que invasores insiram ou manipulem consultas SQL maliciosas.

O SQL Injection está na mesma calçada da fama de DDoS. Aqui na [Wikipedia](https://en.wikipedia.org/wiki/SQL_injection#Examples) você encontra um histórico dos principais ataques.


<picture>
   <source media="(prefers-color-scheme: light)" srcset="https://github.com/agodoi/sqlinjection/blob/main/imgs/sql_injection-01.jpg">
   <img alt="DataStores" src="[YOUR-DEFAULT-IMAGE](https://github.com/agodoi/sqlinjection/blob/main/imgs/sql_injection-01.jpg)">
</picture>


Dependendo da forma que você interage com as aplicações de RDS do seu projeto, o invasor pode apagar seu banco em alguns segundos.

### 1.1) Proteção de Dados Sensíveis
   - O sistema de inventário descrito lida com a sincronização de dados de estoque de vários centros de distribuição e lojas. Proteger o banco de dados contra SQL Injection garante que informações críticas, como quantidades de estoque e detalhes de centros de distribuição, sejam mantidas seguras, impedindo o vazamento de dados internos que poderiam prejudicar a operação.

### 1.2) Maior Confiabilidade do Sistema
   - Ao implementar mecanismos que evitam SQL Injection, como prepared statements ou ORM (Object-Relational Mapping), a confiabilidade do sistema aumenta, pois ele não será vulnerável a manipulações externas. Isso é crucial para garantir que o sistema de inventário distribuído continue funcionando corretamente, sem interferências de usuários maliciosos.

### 1.3) Preservação da Integridade dos Dados
   - Prevenir SQL Injection assegura que os dados no banco permaneçam íntegros. Isso é essencial para o correto funcionamento do sistema de inventário, onde dados de estoque devem ser sincronizados em tempo real. A integridade dos dados é fundamental para evitar discrepâncias no inventário, o que pode resultar em falhas na entrega e no gerenciamento logístico.

### 1.4) Conformidade com Normas de Segurança
   - Empresas como a Vivo estão frequentemente sujeitas a regulamentações de privacidade e segurança de dados (como LGPD). A prevenção de ataques de SQL Injection é uma prática de segurança recomendada que ajuda a empresa a se manter em conformidade com essas normas, evitando multas e danos à reputação.

### 1.5) Redução de Custos com Incidentes de Segurança
   - Investir na prevenção de ataques como o SQL Injection pode evitar incidentes de segurança caros, tanto em termos de reparo de sistemas quanto em possíveis responsabilidades legais. Isso é especialmente importante para um sistema que opera em múltiplas localidades e lida com grandes volumes de transações, como o sistema de inventário distribuído descrito.

### 1.6) Melhoria na Experiência do Usuário Final
   - Um sistema que sofre menos com falhas de segurança e funciona de forma eficiente oferece uma melhor experiência para o usuário final. No caso do e-commerce B2B e B2C, evitar SQL Injection garante que os clientes possam confiar na plataforma e na exatidão dos prazos de entrega e disponibilidade de produtos.

### 1.7) Preparação para Escalabilidade
   - O sistema descrito precisa suportar grandes volumes de transações. Implementar medidas de segurança contra SQL Injection permite que a plataforma escale de forma segura, sem se tornar mais vulnerável à medida que o volume de usuários e transações cresce.




## 2) Como funciona o ataque?

#### 2.1) Um atacante insere código SQL malicioso em um campo de entrada de um site ou aplicação, isto é, ele usa a sua API, a sua aplicação para chegar no seu RDS.

#### 2.2) Esse código é então executado pelo banco de dados, podendo alterar sua operação original.

#### 2.3) Exemplos de ações possíveis

* Recuperação de dados sensíveis;

* Deleção de tabelas,

* Elevação de privilégios no sistema;

* Download completo da sua base.

### Imagine os valores dos celulares sendo alterados para baixo, criando uma corrida frenética nos sites. Ou, um roubo de cartões de crédito + CVC.


#### 2.4) Exemplo de código vulnerável

Imagine uma aplicação como essa de login em um banco de dados.

```
<html>
<head><title>Pagina de Login</title></head>
  <body bgcolor='000000' text='cccccc'>
    <font face='tahoma' color='cccccc'>
    <center><H1>LOGIN</H1>
    <form action='processa_login.asp' method='post'>
      <table>
        <tr><td>Username:</td><td>
        <input type=text name=username size=100% width=100>
        </input></td></tr>
        <tr><td>Password:</td><td>
        <input type=password name=password size=100% width=100>
        </input></td></tr>
      </table>
      <input type=submit name=enviar><input type=reset name=Redefinir>
    </form>
  </body>
</html>

```

<picture>
   <source media="(prefers-color-scheme: light)" srcset="https://github.com/agodoi/sqlinjection/blob/main/imgs/tela_banco_01.png">
   <img alt="Front-end login" src="[YOUR-DEFAULT-IMAGE](https://github.com/agodoi/sqlinjection/blob/main/imgs/tela_banco_01.png)">
</picture>


Se for digitada a entrada:

* Username: godoi
  
* Password: admin12345

A consulta SQL montada será: ```SELECT id FROM users WHERE username='godoi' AND password='admin12345'

Com esta consulta o banco de dados SQL vai procurar por uma linha no banco de dados cuja coluna username seja **godoi** e cuja coluna password seja **admin12345**. Se encontrar, retorna o valor da coluna id para essa linha.

|id|username|password|
|-|-|-|
|1|admin|jklfjdaskfjalk|
|2|godoi|admin12345|
|3|bill|gates|
|4|jeff|beazos|
|5|joao|cabrobro|
|6|ratinho|sbt|

#### Explicação:

```
sql = "SELECT id FROM users WHERE username='" + user + "' AND password='" + pass + "'";
```

- O código está montando uma string SQL de forma dinâmica, concatenando os valores das variáveis ```user``` e ```pass``` diretamente na consulta SQL.
  
- A consulta tenta selecionar o ```id``` de um usuário a partir de uma tabela ```users```, onde o campo ```username``` deve corresponder ao valor da variável ```user```, e o campo ```password``` deve corresponder ao valor da variável ```pass```.

- A expressão ```user + "' AND password='" + pass + "``` insere diretamente os valores de ```user``` e ```pass``` na string SQL. Isso é uma forma arriscada de construir consultas SQL, pois o conteúdo de ```user``` e ```pass``` não está sendo verificado ou tratado de forma segura.


#### 2.5) Exemplo 1 de código malicioso

Imagine que foi digitado o seguinte:

|Variável|Dado|
|-|-|
|Username:| ```godoi```|
|Password:| ```XxxXxxX' OR 1=1```|
| |Falso OR True = True|

#### Lembrando: na Álgebra de Boole, Falso + True = True

<picture>
   <source media="(prefers-color-scheme: light)" srcset="https://github.com/agodoi/sqlinjection/blob/main/imgs/tela_banco_02.png">
   <img alt="Front-end login" src="[YOUR-DEFAULT-IMAGE](https://github.com/agodoi/sqlinjection/blob/main/imgs/tela_banco_02.png)">
</picture>


#### Explicação

* Neste caso, o SQL injection foi usado para contornar a autenticação do usuário.

* O atacante só precisa conhecer o username ```godoi``. Por isso, deve-se evitar o ```admin```

* A consulta SQL montada tem erro de sintaxe (' a mais no final):

```
SELECT id FROM users WHERE username= 'godoi' AND password='XxxXxxX' OR 1=1'
```

* Inserção de comentário: algumas sequências de caracteres são delimitadores de início de comentários:

   - MySQL, MS-SQL, Oracle, PostgreSQL, SQLite:
      * ' OR '1'='1' --
      * ' OR '1'='1' /*
   - MySQL:
      * ' OR '1'='1' #

   - Access (using null characters):
     * ' OR '1'='1' %00
     * ' OR '1'='1' %16

   - Uso de caracteres especiais: se sua aplicações aceita os caracteres especiais, é provável que ela esteja vulnerável. 

      * **'** aspas simples
      * **"** aspas dupla
      * **;** ponto e vírgula


* A condição ```OR 1=1``` sempre será verdadeira, o que pode levar à execução de uma consulta que ignora o nome de usuário e senha corretos, permitindo ao invasor obter acesso sem fornecer uma senha válida.


#### 2.6) Exemplo 2 de código malicioso

Imagine que foi digitado o seguinte:

|Variável|Dado|
|-|-|
|Username:| ```' OR 1=1 --```|
|Password:| ``` ```|
| |Falso OR True = True|

#### Lembrando: na Álgebra de Boole, Falso + True = True

<picture>
   <source media="(prefers-color-scheme: light)" srcset="https://github.com/agodoi/sqlinjection/blob/main/imgs/tela_banco_03.png">
   <img alt="Front-end login" src="[YOUR-DEFAULT-IMAGE](https://github.com/agodoi/sqlinjection/blob/main/imgs/tela_banco_03.png)">
</picture>


#### Explicação

```
SELECT id FROM users WHERE username= ' ' OR 1=1 --' AND password=' '
```

* Nesse caso, nem mesmo username válido é preciso.

* O atacante nem sempre sabe qual servidor SQL está em execução. Assim, a condição **Sempre TRUE** pode variar e é detectado por tentativa e erro:
   - '1'='1' 
   - 1=1
   - =
   - true


* Em SQL, pode-se encadear vários comandos em um separando-os por **;**
   - ```1=1; drop table users```
   - Múltiplas seleções podem ser formadas para um único resultado com o comando UNION

#### 2.7) Ataques em HTTP/GET

Ao se usar HTTP/GET, as variáveis do formulário ficam expostas na barra de navegação e oferecem um ponto de partida para manipulação. Por exemplo:
```http://testphp.vulnweb.com/artists.php?artist=1```

O formulário tem um método **get** que expõe a variável ```artist=1```. Veja a foto e o site [http://testphp.vulnweb.com/artists.php?artist=2](http://testphp.vulnweb.com/artists.php?artist=2)


<picture>
   <source media="(prefers-color-scheme: light)" srcset="https://github.com/agodoi/sqlinjection/blob/main/imgs/tela_banco_04.png">
   <img alt="Front-end login" src="[YOUR-DEFAULT-IMAGE](https://github.com/agodoi/sqlinjection/blob/main/imgs/tela_banco_04.png)">
</picture>

#### 2.5) Exemplo de uma forma mais segura:
   ```
   $stmt = $mysqli->prepare("SELECT id FROM users WHERE username = ? AND password = ?");
   $stmt->bind_param("ss", $user, $pass);
   $stmt->execute();
   $result = $stmt->get_result();
   ```

Neste exemplo, o ```?``` atua como um placeholder para os valores de ```user``` e ```pass```, que são vinculados de maneira segura à consulta usando o método ```bind_param()```. Isso garante que os valores sejam tratados como dados, evitando injeções de SQL.








## 3) Prevenção de SQL Injection usando AWS

### 3.1) Validação de Entrada
   - Filtragem e Sanitização: certifique-se de que todas as entradas sejam validadas e filtradas para eliminar comandos SQL maliciosos. Nunca confie em dados vindos do usuário.
   
   Exemplo de Código Segurizado (Usando Prepared Statements com PHP e MySQL):
   
   ```
   $stmt = $mysqli->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
   $stmt->bind_param("ss", $username, $password);
   $stmt->execute();
   $result = $stmt->get_result();
   ```
   *Usar prepared statements impede que o atacante insira código SQL diretamente na consulta.*
   

No código fornecido, o método **$mysqli->prepare()** está sendo utilizado para criar uma declaração preparada (prepared statement) no banco de dados MySQL com espaços reservados (?) para parâmetros, que serão posteriormente substituídos por valores reais. Isso é útil por vários motivos, especialmente em termos de segurança e eficiência.

Benefícios do **prepare()**:

O uso de uma declaração preparada ajuda a evitar ataques de SQL injection. Com o **prepare()**, os parâmetros **($username e $password)** são tratados como dados e não como parte da consulta SQL. Isso significa que mesmo se um usuário tentar injetar código malicioso, ele será tratado como uma simples string, em vez de ser executado como parte da consulta.

Exemplo: se um usuário tentar inserir um valor como **admin' OR 1=1 --**, ele não conseguirá manipular a consulta SQL, pois essa entrada será tratada como um dado literal.

Em vez de inserir diretamente os valores na string SQL, você usa placeholders (?). Posteriormente, os valores reais são vinculados a esses placeholders com o método bind_param().



### 3.2) Serviços da AWS para Prevenção de SQL Injection

#### 3.2.1) AWS WAF (Web Application Firewall)
   - Função: O AWS WAF ajuda a proteger suas aplicações web contra explorações comuns, incluindo SQL Injection.
   - Como configurar para SQL Injection:
     - No AWS WAF, crie regras personalizadas que bloqueiam ou limitam tentativas de SQL Injection.
     - Habilite a regra "SQL Injection Match Condition", que detecta padrões comuns de injeções de SQL nas requisições.

     Exemplo de configuração:
     - Adicione uma regra de SQL Injection à ACL do AWS WAF.
     - Associe essa ACL à distribuição do Amazon CloudFront ou ao API Gateway.

---

##### 3.2.2) Amazon RDS (Relational Database Service)
   - Função: Gerenciamento seguro de bancos de dados, com encriptação automática de dados e proteção contra falhas de segurança comuns.
   - Configurações para melhorar a segurança:
     - IAM Authentication: Use autenticação baseada no IAM para evitar senhas SQL hardcoded.
     - Encrypted connections: Garanta que as conexões com o banco sejam feitas via SSL para impedir interceptações.
     - Auditoria de Logs: Ative logs de auditoria para monitorar e registrar consultas suspeitas.

---

##### 3.2.3) Amazon Cognito
   - Função: Gerenciamento de autenticação de usuários com foco na segurança.
   - Como ajuda a prevenir SQL Injection:
     - Cognito permite que sua aplicação autentique usuários sem precisar manipular diretamente as senhas no código-fonte. Isso reduz o risco de injeções maliciosas em campos sensíveis.
     - Integre a autenticação com Cognito para criar uma camada extra de segurança.

---

##### 3.2.4) AWS Secrets Manager
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



## X) Outras Boas Práticas de Segurança na AWS
   - Least Privilege Principle (Princípio do Menor Privilégio): Assegure-se de que os usuários e aplicações tenham apenas as permissões necessárias. Evite dar privilégios administrativos sem necessidade.
   - Multi-Factor Authentication (MFA): Habilite MFA para usuários IAM para aumentar a segurança das credenciais.
   - Security Groups & NACLs: Limite o acesso ao banco de dados usando regras de Security Groups e Network ACLs, permitindo apenas o tráfego necessário.
   - Monitoramento com CloudWatch e GuardDuty: Monitore atividades incomuns e potencialmente maliciosas em suas aplicações e infraestrutura, incluindo tentativas de SQL Injection.

---


