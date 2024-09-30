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


#### 2.4) Exemplo de código malicioso

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
   <source media="(prefers-color-scheme: light)" srcset="https://github.com/agodoi/sqlinjection/blob/main/imgs/tela_banco_01.jpg">
   <img alt="Front-end login" src="[YOUR-DEFAULT-IMAGE](https://github.com/agodoi/sqlinjection/blob/main/imgs/tela_banco_01.jpg)">
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

- A expressão ```user + "' AND password='" + pass + "``` insere diretamente os valores de ```user``` e ```pass``` na string SQL. Isso é uma forma arriscada de construir consultas SQL, pois o conteúdo de ```user``` e ```pass``` não está sendo verificado ou tratado de forma segura. **Exemplo de ataque:** se um usuário mal-intencionado passar o seguinte valor para ```user```:

     ```
     user = "admin' OR 1=1 --"
     ```
     A consulta final gerada seria:
  
     ```
     SELECT id FROM users WHERE username='admin' OR 1=1 --' AND password='';
     ```

- Neste caso, a condição `OR 1=1` sempre será verdadeira, o que pode levar à execução de uma consulta que ignora o nome de usuário e senha corretos, permitindo ao invasor obter acesso sem fornecer uma senha válida.

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

---

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



## 3) Exemplo básico de SQL Injection (logando como administrador)

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

### 3.1) Uso de caracteres especiais

Se sua aplicações aceita os caracteres especiais, é provável que ela esteja vulnerável. 

* **'** aspas simples
* **"** aspas dupla
* **;** ponto e vírgula


### 4) Passos

# Passo-01: Criando a VPC

**1.1)** Busque por VPC no console da AWS;

**1.2)** Clique no botão laranja CRIAR;

**1.3)** Selecione **Somente VPC**.

**1.4)** No campo **Tag de nome** digite **VPC_Arquitetura_Corp**.

**1.5)** Bloco CIDR IPV4 digite **192.168.0.0/22**

**1.6)** As demais opções, você não precisa mexer e basta confirmar no botão laranja.


# Passo-02: Criando as sub-redes
## sub-rede pública

**2.1)** No menu vertical da VPC, clique em **sub-redes** e então, clique no botão laranja **Criar sub-redes** e aponte para a VPC corporativa que acabou de criar **VPC_Arquitetura_Corp**.

**2.2)** No campo **Nome da sub-rede** coloque **Sub_Publica_a**.

**2.3)** Em **Zona de disponibilidade** deixe **us-east-1a**.

**2.4)** Em **Bloco CIDR IPV4** coloque um IP que esteja dentro da faixa da rede da VPC que você criou, então, **digite 192.168.0.0/24**. Essa faixa está dentro da faixa maior 192.168.0.0/22. Vamos discutir o mapa de endereçamento numa instrução futura. Aguente firme! Clique no botão laranja.

## sub-rede privada

**2.5)** Repetindo os passos para criar a Rede Privada, no menu vertical da VPC, clique em **sub-redes** e então, aponte para a VPC corporativa que acabou de criar **VPC_Arquitetura_Corp**.

**2.6)** No campo **Nome da sub-rede** coloque **Sub_Privada_a**. Note que você está apontado para uma zona diferente da sua sub-rede pública. É uma estratégia para 
[alta disponibilidade](https://github.com/agodoi/VocabularioAWS).

**2.7)** Em **Zona de disponibilidade** deixe **us-east-1a**.

**2.8)** Em **Bloco CIDR IPV4** coloque um IP que esteja dentro da faixa da rede da VPC que você criou, então, **digite 192.168.1.0/24**. Essa faixa está dentro da faixa maior 192.168.0.0/22. Novamente, vamos discutir o mapa de endereçamento numa instrução futura.


**3.2)** Clique em **Criar tabela de rotas**, e em **nome** coloque **TabRota_Publica_ArqCorp** e selecione a VPC recém criada e confirme no botão laranja.

**3.3)** Faça o mesmo para a sua subnet privada. Clique em **Criar tabela de rotas**, e em **nome** coloque **TabRota_Privada_ArqCorp** e selecione a VPC recém criada e confirme no botão laranja.

Até agora, você só criou os nomes das Tabelas de Rotas que não sabem o que fazer ainda. Elas apenas estão dentro da sua VPC recém criada **VPC_Arquitetura_Corp**.

**3.4)** Vamos agora associar as Tabelas de Rotas com as sub-redes propriamente ditas.

**3.4.1)** Clique no link azul da tabela de rotas privada **TabRota_Privada_ArqCorp**, vá na aba **Associação de sub-rede**, clique no botão **Editar associações de sub-rede** e selecione a sub-rede privada **Sub_Privada_b** e confirme no botão laranja.

**3.4.2)** Faça o mesmo para a tabela de rotas pública **TabRota_Publica_ArqCorp**, clicando em seu link azul, depois indo na aba **Associação de sub-rede**, clicando no botão **Editar associações de sub-rede** e selecione a sub-rede privada **Sub_Publica_a** e confirme no botão laranja.

# Passo-04: Criando o IGW

Esse elemento de rede resolve como sua rede pública vai encontrar a Internet.

**4.1)** Para criar uma saída para Internet da sub-rede pública, vá no menu vertical esquerdo da VPC, clique em **Gateways da Internet**, depois **Criar gateway da Internet** e em **Tag name** digite **IGW_ArqCorp** e confirme no botão laranja. Cuidado agora! Você precisa associar o seu IGW à VPC_Arquitetura_Corp. Então clique no botão verde que vai aparecer na barra superior ou volte no menu vertical esquerdo, liste o seu **Gateways da Internet**, vá no botão **Ações**, selecione **Associar à VPC** e escolha a VPC recém criada e confirma no botão laranja.

**4.2)** Volte na tabela de rotas **TabRota_Publica_ArqCorp** para indicar as regras de entrada e saída da sua VPC. Então, vá no menu esquerdo vertical, clique em **Tabela de Rotas** e escolha a **TabRota_Publica_ArqCorp**, e depois, vá na aba **Rotas**. Já existe uma rota padrão interna 192.168.0.0/22 mas isso não dá acesso externo à sua VPC e sim, somente acesso interno. Clique em **Editar rota**, depois **Adicionar rota** e selecione em **destino** 0.0.0.0/0 (que significa qualquer lugar) e em **alvo** você seleciona **Gateway da Internet** e daí vai aparecer a sua o **IGW_ArqCorp**, daí vc o seleciona e coloque para salvar no botão laranja.


# Passo-05: Criando o NAT
Agora vamos resolver o acesso à Internet da sub-rede privada, porém, acesso de saída. Não de entrada, por enquanto.

**5.1)** No menu vertical da VPC, clique na opção **Gateways NAT**, depois clique no botão **Criar gateway NAT**, e depois, em nome coloque **NAT_ArqCorp** e na opção **sub-rede** você aponta para a **sub-rede pública**. Note que existe uma opção chamada **Tipo de conexão** que já está pré-marcada em **Público** e é isso que garante que sua sub-rede privada poderá acessar à Internet. Existe a opção também de **Alocar IP elástico**, então clique nesse botão **Alocar IP elástico** para gerar um IP elástico e daí você terá a opção como **eipalloc-xxxxxxxx**. Finalmente, clique no botão laranja para confirmar tudo.

**5.2)** No meu vertical esquerdo da sua VPC, clique em **Tabela de rotas**, clique no link azul **TabRota_Privada_ArqCorp** e daí, **Editar rotas**, clique no botão **Adicionar rotas**, escolha o **Destino 0.0.0.0/0** (Internet externa) e coloque em **Alvo** como **Gateway NAT** (algo do tipo assim **nat-0f1c0fbcfded07cf8** vai aparecer). **Esse item gasta-se alguns minutos para propagar e começar a funcionar.**

   



**4.1)** No seu Learner Lab, crie uma instância do RDS:

**4.2)** No painel do Amazon RDS, vá no menu à esquerda, clique em **Bancos de dados**, e depois, clique em **Criar banco de dados**;

**4.3)** Escolha o modo padrão para tudo, como **MySQL**;

**4.4)** Em **Modelos**, marque **Níve Gratuito**;

**4.4)** Deixe todas as opções originais sem mexer, apenas coloque um nome no seu banco trocando o **database-1** por meu **meuBancoExposto**;

4.5) Em Nome do usuário principal, deixe **admin** (tudo minúsculo);

4.6) Crie uma senha fácil **admin12345**

4.7) Crie uma EC2 básico, usando sistema operacional Ubuntu, salve a chave **pem** no seu PC, coloque na VPC que você acabou de criar, coloque na sub-rede privada que criou. Quando você amarrar o seu EC2 à VPC, e depois, amarrar o seu RDS ao EC2, automaticamente, seu RDS estará na sua VPC.

4.8) Na opção **Nuvem privada virtual (VPC)**, deve aparecer o nome da sua VPC após associar ao EC2. Em **Grupos de sub-rede de banco de dados**, deixe **Configuração automática**.

**4.7)** Em **Grupos de segurança da VPC (firewall)**, deixe **Selecionar existente**;

**4.8)** Não mexa em mais nenhum opção, e cliquem em **Criar banco de dados**.


4.4) Selecione a classe do banco de dados (como db.t3.micro para testes gratuitos).
Defina as configurações de rede (VPC, sub-redes) e as credenciais de administrador (nome de usuário e senha).
Habilite a opção de "Acesso público" para que você possa acessar o banco de dados externamente durante o teste.
Defina o tamanho de armazenamento de acordo com suas necessidades (pode ser o mínimo para testes).
1.3. Configurar Regras de Segurança
Crie um Security Group para a instância de RDS que permita o tráfego de entrada na porta 3306 (para MySQL).
Garanta que seu IP ou a rede da aplicação tenha acesso à instância do banco de dados.
1.4. Criar a Tabela de Usuários no Banco
Após a instância estar ativa, conecte-se ao banco de dados usando um cliente de banco de dados (como MySQL Workbench ou DBeaver) com as credenciais que você criou.
Crie uma tabela de usuários simples com um campo de nome de usuário, senha e função (normal ou admin). Exemplo de SQL para criar a tabela:












## X) Outras Boas Práticas de Segurança na AWS
   - Least Privilege Principle (Princípio do Menor Privilégio): Assegure-se de que os usuários e aplicações tenham apenas as permissões necessárias. Evite dar privilégios administrativos sem necessidade.
   - Multi-Factor Authentication (MFA): Habilite MFA para usuários IAM para aumentar a segurança das credenciais.
   - Security Groups & NACLs: Limite o acesso ao banco de dados usando regras de Security Groups e Network ACLs, permitindo apenas o tráfego necessário.
   - Monitoramento com CloudWatch e GuardDuty: Monitore atividades incomuns e potencialmente maliciosas em suas aplicações e infraestrutura, incluindo tentativas de SQL Injection.

---

### 6. Exercício Prático
