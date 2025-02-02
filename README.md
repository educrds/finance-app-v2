

# **Coinz**

Uma aplicação completa para o gerenciamento de finanças pessoais, desenvolvida com tecnologias modernas para oferecer uma experiência intuitiva, segura e eficiente.

----------

## **Índice**

1.  [Visão Geral](#vis%C3%A3o-geral)
2.  [Funcionalidades](#funcionalidades)
3.  [Tecnologias Utilizadas](#tecnologias-utilizadas)
4.  [Autenticação e Segurança](#autentica%C3%A7%C3%A3o-e-seguran%C3%A7a)

----------

## **Visão Geral**

A ideia para esta aplicação surgiu de uma necessidade pessoal de gerenciar melhor meus gastos mensais. Criar um controle eficiente e detalhado tornou-se essencial, e com isso desenvolvi esta aplicação. Atualmente, ela atende plenamente essa necessidade, proporcionando praticidade e organização no gerenciamento das minhas finanças.

Este projeto tem como objetivo auxiliar no controle financeiro pessoal, oferecendo ferramentas para registrar e visualizar receitas, despesas e relatórios financeiros. Com uma interface moderna e visualizações dinâmicas, a aplicação proporciona uma gestão mais prática e detalhada das finanças.

![image](https://github.com/user-attachments/assets/16a740b9-9f04-46b5-aa47-1491554efdd4)


----------

## **Funcionalidades**

-   **Gerenciamento de Receitas e Despesas:** Cadastre entradas e saídas financeiras organizadas por categoria.
-   **Gráficos Interativos:** Visualize dados financeiros de maneira dinâmica e clara.
-   **Relatórios Financeiros:** Geração de relatórios para análise detalhada de gastos e receitas.
-   **Interface Responsiva:** Navegação otimizada para dispositivos móveis e desktops.
-   **Autenticação Segura:** Login e gerenciamento de sessões com autenticação moderna.

----------

## **Tecnologias Utilizadas**

A aplicação foi construída utilizando ferramentas modernas para oferecer uma experiência confiável e eficiente:

### **Front-End**

-   **[Angular 18](https://angular.io/):** Framework robusto que garante a criação de interfaces escaláveis, rápidas e dinâmicas.
-   **[PrimeNG](https://primeng.org/):** Biblioteca de componentes UI altamente customizáveis, utilizados para criar uma interface intuitiva e responsiva.
-   **[Chart.js](https://www.chartjs.org/):** Tecnologia para gráficos interativos e dinâmicos, permitindo uma visualização clara e impactante das informações financeiras.

### **Back-End**

-   **[Node.js](https://nodejs.org/):** Plataforma eficiente para execução de código JavaScript no servidor.
-   **[Express](https://expressjs.com/):** Framework ágil e minimalista, utilizado para criar APIs REST robustas e performáticas.
-   **[MariaDB](https://mariadb.org/):** Banco de dados relacional poderoso e de alta performance, ideal para o armazenamento seguro das informações financeiras.

----------
## **Autenticação e Segurança**

A segurança dos dados dos usuários é uma prioridade na aplicação. Por isso, foram implementados mecanismos modernos para autenticação e proteção:

### **Auth0: Autenticação Moderna e Confiável**

-   **Google Login:** Login rápido e seguro utilizando a conta Google com suporte a Single Sign-On (SSO).
-   **Email e Senha:** Método alternativo para usuários que preferem criar uma conta com autenticação personalizada.
-   **Gerenciamento de Sessões:** A cada login, um token JWT é gerado, válido por 1 dia, garantindo o acesso seguro e controlado aos recursos da aplicação.

### **Criptografia de Senhas com bcrypt**

-   As senhas são protegidas com hash criptográfico utilizando **bcrypt**, adicionando uma camada extra de segurança aos dados armazenados no banco.

Com essas soluções, a aplicação oferece uma experiência de login prática e confiável, sem comprometer a privacidade e segurança dos usuários.

----------


## **Demonstração da Aplicação**

Abaixo estão alguns vídeos demonstrando o funcionamento da aplicação, desde a criação de transações até a autenticação e navegação entre páginas. Cada vídeo apresenta um recurso essencial da plataforma, auxiliando no entendimento das funcionalidades disponíveis.

### **Criação de Transações Parceladas**
Aprenda a registrar uma transação parcelada dentro do sistema, configurando corretamente a quantidade de parcelas e categorizando a despesa. Essa funcionalidade facilita o acompanhamento de pagamentos recorrentes ao longo do tempo.
[Assista aqui](https://coinzapp.s3.us-east-2.amazonaws.com/demo2+coinz.mp4)

### **Autenticando Novo Usuário**
Demonstração do processo de criação de uma conta e login na aplicação, garantindo a segurança do acesso por meio de autenticação moderna, incluindo suporte para login via Google e e-mail/senha.
[Assista aqui](https://coinzapp.s3.us-east-2.amazonaws.com/demo+register.mp4)

### **Criação de Despesas e Receitas**
Saiba como adicionar novas despesas e receitas ao sistema, categorizando corretamente cada lançamento para um controle financeiro mais organizado e eficiente.
[Assista aqui](https://coinzapp.s3.us-east-2.amazonaws.com/demo+criacao+receita+e+despesa.mp4)

### **Alternando entre Páginas e Criando Nova Categoria**
Demonstração da navegação intuitiva entre diferentes páginas da aplicação e do processo de criação de uma nova categoria financeira, permitindo personalizar o gerenciamento de transações conforme a necessidade do usuário.
[Assista aqui](https://coinzapp.s3.us-east-2.amazonaws.com/Alternando+entre+paginas+e+criacao+de+categoria.mp4)

### **Utilização da Nova Categoria**
Veja como associar uma transação a uma categoria recém-criada, garantindo um controle mais preciso das finanças e melhorando a organização dos registros.
[Assista aqui](https://coinzapp.s3.us-east-2.amazonaws.com/uso+nova+categoria.mp4)
