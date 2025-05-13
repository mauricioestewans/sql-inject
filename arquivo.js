<script>
// Simule que os dados estão em formato de texto
var data = "Username, Password\n";  // Cabeçalho
data += "user1, pass1\n";           // Exemplo de dados
data += "user2, pass2\n";           // Exemplo de dados

// Cria um Blob com os dados (arquivo em memória)
var blob = new Blob([data], { type: 'text/plain' });

// Cria um link de download
var link = document.createElement('a');
link.href = URL.createObjectURL(blob);
link.download = 'usuarios.txt';  // Nome do arquivo a ser baixado
link.click();  // Simula um clique para iniciar o download
</script>