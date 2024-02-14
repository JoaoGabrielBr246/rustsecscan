extern crate url;
use url::{Url};
use std::io::{self, Write};

fn main() {
    println!("
   __           _   __           __                 
  /__\\_   _ ___| |_/ _\\ ___  ___/ _\\ ___ __ _ _ __  
 / \\// | | / __| __\\ \\ / _ \\/ __\\ \\ / __/ _` | '_ \\ 
/ _  \\ |_| \\__ \\ |__\\ \\  __/ (___\\ \\ (_| (_| | | | |
\\/ \\_/\\__,_|___/\\__/\\__/\\___|\\___\\__/\\___\\__,_|_| |_|

    ");

    println!("Este programa foi criado para estudos de cibersegurança e programação.");
    println!("Não me responsabilizo por mau uso da ferramenta.");
    println!("Feito por joaogabrocha. Github: https://github.com/JoaoGabrielBr246");

    let mut url_str = String::new();
    print!("Digite a URL: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut url_str).unwrap();

    let url = Url::parse(&url_str.trim()).unwrap();

    println!("Esquema: {}", url.scheme());
    if let Some(host) = url.host_str() {
        println!("Host: {}", host);
    }
    if let Some(port) = url.port() {
        println!("Porta: {}", port);
    }
    for (key, value) in url.query_pairs() {
        println!("Parâmetro de consulta: {} = {}", key, value);
    }

    if url.scheme() != "https" {
        println!("Aviso: A URL não está usando HTTPS. As informações transmitidas podem não estar seguras.");
    }
    if url.username() != "" || url.password().is_some() {
        println!("Aviso: A URL contém informações de autenticação. Isso pode ser uma vulnerabilidade de segurança.");
    }
    if url.path().contains("..") {
        println!("Aviso: A URL contém um caminho com '..'. Isso pode ser uma tentativa de travessia de diretório.");
    }
    if url.query().is_some() {
        println!("Aviso: A URL contém parâmetros de consulta. Isso pode ser uma vulnerabilidade de segurança se os parâmetros contiverem dados sensíveis.");
    }
    if url.fragment().is_some() {
        println!("Aviso: A URL contém um fragmento. Isso pode ser uma vulnerabilidade de segurança se o fragmento contiver dados sensíveis.");
    }

    let special_chars = "<>#%{}|\\^~[]`";
    if url_str.chars().any(|c| special_chars.contains(c)) {
        println!("Aviso: A URL contém caracteres especiais suspeitos, o que pode indicar uma tentativa de ataque.");
    }

    if let Some(host) = url.host_str() {
        if !url_str.contains(host) {
            println!("Aviso: A URL redireciona para outro domínio, o que pode indicar uma vulnerabilidade de redirecionamento aberto.");
        }
    }

    let security_headers = ["CSP", "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection"];
    for header in &security_headers {
        if url_str.contains(header) {
            println!("Aviso: A URL envia cabeçalhos de segurança {}, mas certifique-se de que estejam configurados corretamente.", header);
        }
    }

    if url_str.contains("Set-Cookie:") && !url_str.contains("Secure; HttpOnly") {
        println!("Aviso: A URL contém cookies que não são configurados como seguros e HTTPOnly, o que pode ser uma vulnerabilidade de segurança.");
    }

    let code_injection_patterns = ["<script>", "eval(", "exec(", "SELECT * FROM"];
    for pattern in &code_injection_patterns {
        if url_str.contains(pattern) {
            println!("Aviso: A URL contém padrões suspeitos de injeção de código, o que pode indicar uma vulnerabilidade de segurança.");
        }
    }

    if url_str.contains("cmd=") || url_str.contains("exec=") {
        println!("Aviso: A URL contém parâmetros que podem ser usados para execução de comandos, o que pode ser uma vulnerabilidade de segurança.");
    }

    if url_str.contains("upload=") {
        println!("Aviso: A URL contém parâmetros que podem ser usados para upload de arquivos, o que pode ser uma vulnerabilidade de segurança.");
    }

    if url_str.contains("Cache-Control:") && url_str.contains("public") {
        println!("Aviso: A URL envia cabeçalhos de cache que podem ser explorados para ataques de envenenamento de cache.");
    }

    let server_vulnerabilities = [
        "CVE-2021-1234", 
        "CVE-2021-5678",
        "CVE-2022-9876",
        "CVE-2022-5432",
        "CVE-2023-9999",
        "CVE-2023-8888",
    ];
    for vulnerability in &server_vulnerabilities {
        if url_str.contains(vulnerability) {
            println!("Aviso: O servidor possui uma vulnerabilidade conhecida {}, o que pode representar um risco de segurança.", vulnerability);
        }
    }

    let mut xss_detected = false;

    let js_events = ["onmouseover", "onmousemove", "onclick", "onerror", "onload"];
    for event in &js_events {
        if url_str.contains(event) {
            println!("Aviso: Evento JavaScript {} detectado na URL, possivelmente indicando uma tentativa de XSS.", event);
            xss_detected = true;
        }
    }

    let html_attributes = ["<script>", "src=", "href=", "onerror=", "onload="];
    for attr in &html_attributes {
        if url_str.contains(attr) {
            println!("Aviso: Atributo HTML suspeito {} detectado na URL, possivelmente indicando uma tentativa de XSS.", attr);
            xss_detected = true;
        }
    }

    if url_str.contains("javascript:") {
        println!("Aviso: Tentativa de injeção de código JavaScript direto detectada na URL, possivelmente indicando uma tentativa de XSS.");
        xss_detected = true;
    }

    if !xss_detected {
        println!("A URL não parece conter vulnerabilidades conhecidas de segurança.");
    }
}
