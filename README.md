<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Coinz - Gerenciamento Financeiro</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 40px;
            line-height: 1.6;
        }
        h1, h2, h3 {
            color: #333;
        }
        hr {
            margin: 20px 0;
        }
        ul {
            list-style: none;
            padding: 0;
        }
        ul li::before {
            content: "\2022";
            color: #007BFF;
            font-weight: bold;
            display: inline-block; 
            width: 1em;
            margin-left: -1em;
        }
        a {
            color: #007BFF;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <h1><strong>Coinz</strong></h1>
    <p>Uma aplicação completa para o gerenciamento de finanças pessoais, desenvolvida com tecnologias modernas para oferecer uma experiência intuitiva, segura e eficiente.</p>
    <hr>
    
    <h2><strong>Índice</strong></h2>
    <ul>
        <li><a href="#visao-geral">Visão Geral</a></li>
        <li><a href="#funcionalidades">Funcionalidades</a></li>
        <li><a href="#tecnologias-utilizadas">Tecnologias Utilizadas</a></li>
        <li><a href="#autenticacao-e-seguranca">Autenticação e Segurança</a></li>
    </ul>
    <hr>
    
    <h2 id="visao-geral"><strong>Visão Geral</strong></h2>
    <p>A ideia para esta aplicação surgiu de uma necessidade pessoal de gerenciar melhor meus gastos mensais. Criar um controle eficiente e detalhado tornou-se essencial, e com isso desenvolvi esta aplicação. Atualmente, ela atende plenamente essa necessidade, proporcionando praticidade e organização no gerenciamento das minhas finanças.</p>
    <p>Este projeto tem como objetivo auxiliar no controle financeiro pessoal, oferecendo ferramentas para registrar e visualizar receitas, despesas e relatórios financeiros. Com uma interface moderna e visualizações dinâmicas, a aplicação proporciona uma gestão mais prática e detalhada das finanças.</p>
    <hr>
    
    <h2 id="funcionalidades"><strong>Funcionalidades</strong></h2>
    <ul>
        <li><strong>Gerenciamento de Receitas e Despesas:</strong> Cadastre entradas e saídas financeiras organizadas por categoria.</li>
        <li><strong>Gráficos Interativos:</strong> Visualize dados financeiros de maneira dinâmica e clara.</li>
        <li><strong>Relatórios Financeiros:</strong> Geração de relatórios para análise detalhada de gastos e receitas.</li>
        <li><strong>Interface Responsiva:</strong> Navegação otimizada para dispositivos móveis e desktops.</li>
        <li><strong>Autenticação Segura:</strong> Login e gerenciamento de sessões com autenticação moderna.</li>
    </ul>
    <hr>
    
    <h2 id="tecnologias-utilizadas"><strong>Tecnologias Utilizadas</strong></h2>
    <h3><strong>Front-End</strong></h3>
    <ul>
        <li><a href="https://angular.io/">Angular 18</a> - Framework robusto que garante a criação de interfaces escaláveis, rápidas e dinâmicas.</li>
        <li><a href="https://primeng.org/">PrimeNG</a> - Biblioteca de componentes UI altamente customizáveis.</li>
        <li><a href="https://www.chartjs.org/">Chart.js</a> - Tecnologia para gráficos interativos e dinâmicos.</li>
    </ul>
    
    <h3><strong>Back-End</strong></h3>
    <ul>
        <li><a href="https://nodejs.org/">Node.js</a> - Plataforma eficiente para execução de código JavaScript no servidor.</li>
        <li><a href="https://expressjs.com/">Express</a> - Framework ágil e minimalista para criação de APIs REST.</li>
        <li><a href="https://mariadb.org/">MariaDB</a> - Banco de dados relacional poderoso e de alta performance.</li>
    </ul>
    <hr>
    
    <h2 id="autenticacao-e-seguranca"><strong>Autenticação e Segurança</strong></h2>
    <p>A segurança dos dados dos usuários é uma prioridade na aplicação. Por isso, foram implementados mecanismos modernos para autenticação e proteção.</p>
    
    <h3><strong>Auth0: Autenticação Moderna e Confiável</strong></h3>
    <ul>
        <li><strong>Google Login:</strong> Login rápido e seguro utilizando a conta Google com suporte a Single Sign-On (SSO).</li>
        <li><strong>Email e Senha:</strong> Método alternativo para usuários que preferem criar uma conta com autenticação personalizada.</li>
        <li><strong>Gerenciamento de Sessões:</strong> A cada login, um token JWT é gerado, válido por 1 dia, garantindo o acesso seguro e controlado aos recursos da aplicação.</li>
    </ul>
    
    <h3><strong>Criptografia de Senhas com bcrypt</strong></h3>
    <p>As senhas são protegidas com hash criptográfico utilizando <strong>bcrypt</strong>, adicionando uma camada extra de segurança aos dados armazenados no banco.</p>
    <p>Com essas soluções, a aplicação oferece uma experiência de login prática e confiável, sem comprometer a privacidade e segurança dos usuários.</p>
    <hr>
    
    <h2><strong>Demonstração</strong></h2>
    <video src="https://github.com/rayytsn9/ROBOTT/assets/79029536/62f541aa-aa8c-43f5-9ead-4b7a2e0d7c2a" width="300" controls></video>
</body>
</html>
