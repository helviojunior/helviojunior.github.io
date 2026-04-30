---
layout: post
title: Tratando código CNL para ligações conurbadas no Asterisk e FreePBX
date: 2016-07-02 09:55:54.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Asterisk
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/voip/asterisk/tratando-codigo-cnl-para-ligacoes-no-asterisk/"
---

## Introdução e contextualização

Antes de qualquer coisa vamos direto ao problema que pretendemos resolver neste post. O sistema de telefonia fixa no Brasil adota um padrão de separação das localidades e uma subordinação político-administrativa (isso será explicado um pouco mais a frente com mais detalhes). Basicamente com essa separação poderemos ter 2 municípios com o mesmo DDD onde para realizar ligações um deles não é necessário adicionar o código de DDD, e para outro sim.

Exemplo: Moro na cidade de Curitiba (cujo DDD é 41), temos diversos municípios de Curitiba e região metropolitana como Curitiba, Lapa, São José dos Pinhais, Colombo e etc... Quando em Curitiba não necessito utilizar o DDD para efetuar uma ligação a estes municípios, porém quando ligamos para Paranaguá, uma cidade a +- 100 Km de Curitiba, que utiliza o mesmo DDD, ja é necessário utilizar o DDD para realizar ligações.

Sendo assim surge o nosso problema, se o DDD não é quem difere se devo ou não colocar o DDD ao realizar uma chamada, como podemos realizar essa distinção? A resposta esta na base de dados CNL.

<!--more-->

Mas ai surge a pergunta o que é CNL? CNL é o acronimo de "Cadastro Nacional de Localidades", que tem como definição legal no Inciso III do art. 3º do anexo da Resolução da Anatel nº 83, de 30/12/1998 como "Conjunto de informações relativo às disponibilidades de serviços de telecomunicações em localidades do território nacional.".

Na pratica o Cadastro de Localidades Brasileira, fornece os nomes, a subordinação político-administrativa (a que grande região, estado, meso ou microrregião pertencem), as coordenadas (latitudes e longitudes) e altitudes médias das sedes de localidades como municípios, vilas, assentamentos rurais e aldeias indígenas, entre outras.

Agora que conhecemos um pouco mais da estruturação da telefonia podemos entrar no detalhamento da base de dados CNL, para posteriormente entender como poderemos distinguir se nossa ligação deve ou não utilizar DDD.

## Atualizações

- 2017-05-15
  - Alteração da biblioteca de download do arquivo para usar CURL;
  - Correção de erro SSL no download do site da Anatel;
  - Correção de erro HTTP 100-Continue;
  - Alteração para usar HTTPS ao invés de HTTP.
- 2017-09-30
  - Corrigido bug de parse no PHP 5.3;
  - Incluído padronização para utilização em FreePBX

## Entendendo o arquivo CNL

A base CNL pode ser baixada a qualquer momento através do link [http://sistemas.anatel.gov.br/areaarea/N_Download/Tela.asp?varMod=Publico&SISQSmodulo=7179](http://sistemas.anatel.gov.br/areaarea/N_Download/Tela.asp?varMod=Publico&SISQSmodulo=7179) selecionando como tipo de arquivo Central CNL, tipo de central Fixo e sigla UF Todas conforme a imagem abaixo:

[![asterisk_cnl_001]({{ site.baseurl }}/assets/2016/07/asterisk_cnl_001-300x215.png)]({{ site.baseurl }}/assets/2016/07/asterisk_cnl_001-300x215.png)

Este processo realizará o download de um arquivo ZIP e detro deste conterá 2 arquivos: Um documento com o layout do arquivo texto, e o arquivo texto contendo a base de dados CNL completa.

[![asterisk_cnl_002]({{ site.baseurl }}/assets/2016/07/asterisk_cnl_002.png)]({{ site.baseurl }}/assets/2016/07/asterisk_cnl_002.png)

Abrindo o arquivo DOC temos o seguinte conteúdo

```text
-----------------------------------------------------------
ANATEL - AGENCIA NACIONAL DE TELECOMUNICACOES
LAY-OUT DO ARQUIVO CE_F_HHMMSS.TXT
-----------------------------------------------------------
ID NOME DO CAMPO                       TIPO TAMANHO
-- ----------------------------------  ---- -------
01 Sigla UF                            char 02
02 Sigla CNL                           char 04
03 Codigo CNL                          char 05
04 Nome da Localidade                  char 50
05 Nome do Municipio                   char 50
06 Cod. da Area Tarifacao              char 05
07 Prefixo                             char 07
08 Prestadora                          char 30
09 Num. da Faixa Inicial               char 04
10 Num. da Faixa Final                 char 04
11 Latitude                            char 08 (*)
12 Hemisferio                          char 05
13 Longitude                           char 08 (*)
14 Sigla CNL da Área Local             char 04

OBSERVAÇÕES:
1) Os campos marcados com (*), Latitude e Longitude foram
   alterados para o formato GGMMSSCC,
   onde:
   GG = Grau,
   MM = Minuto,
   SS = Segundo e
   CC = Centésimos de Segundo
```

Agora abrindo o arquivo texto com a base CNL, extrai 3 linhas para exemplificar e ilustrar como poderemos identificar se devemos ou não colocar DDD em nossas ligações.

As linhas são:

```text
PRCTA 41000CURITIBA                                          CURITIBA                                          412  412027 Aerotech                      0   999 25254692S    49161884CTA
PRSJP 41585SÃO JOSÉ DOS PINHAIS                              SÃO JOSÉ DOS PINHAIS                              412  412094 INTELIG TELECOM               0   999 25315268S    49121115CTA
PRPNG 41464PARANAGUÁ                                         PARANAGUÁ                                         414  412152 CLARO S.A.                    0   999 25305796S    48312100PNG
```

Para o nosso propósito vou extrair alguns trechos das nossas linhas conforme abaixo:

- Linha 1:
  - Campo 05 (Município): Curitiba
  - Campo 07 (Prefixo): 412027
  - Campo 15 (Sigla CNL da Área Local): CTA
- Linha 2:
  - Campo 05 (Município): São José dos Pinhais
  - Campo 07 (Prefixo): 412094
  - Campo 15 (Sigla CNL da Área Local): CTA
- Linha 3:
  - Campo 05 (Município): Paranaguá
  - Campo 07 (Prefixo): 412152
  - Campo 15 (Sigla CNL da Área Local): PNG

Observem que as 3 linhas detêm no prefixo o mesmo DDD (41), porém Paranaguá detêm uma Sigla CNL da Área Local diferente de Curitiba e São José dos Pinhais, isso indica que qualquer ligação vinda de Curitiba para Paranaguá (ou vice versa) deve conter o DDD, ja entre Curitiba e São José dos Pinhais não se faz necessário a utilização do DDD. Sendo assim teremos que analisar não somente o DDD mas o prefixo completo para poder diagnosticar de que cidade é o número que desejamos discar.

## Pré-requisitos

- PHP cli v5.5.9
- MySQL v5.5.47

Caso desje segue abaixo os comandos de instalação dos pré-requisitos

**MySQL v5.7 + PHP v.7.0**

```bash
sudo apt-get install mysql-client-5.7 mysql-server-5.7
sudo apt-get install php7.0-cli php7.0-mysql php7.0-zip php7.0-mbstring php7.0-xml
```

**Versões anteriores**

Caso deseje outra versão do MySQL utilize este procedimento ([http://www.helviojunior.com.br/it/mysql/instalando-e-otimizando-mysql-para-alto-trafego-de-dados/](http://www.helviojunior.com.br/it/mysql/instalando-e-otimizando-mysql-para-alto-trafego-de-dados/))

```bash
sudo apt-get install php5-cli php5-mysql libxml2-dev
```

Os scripts abaixo foram testados no Ubuntu 14.04 com PHP cli v5.5.9 e MySQL v5.5.47 bem como no Ubuntu 16.02 com PHP cli v7.0.4 e MySQL v5.7.12

## Criando estrutura de base de dados e importação

Agora que temos todo o conhecimento do arquivo da base vamos as operações técnicas. Desenvolvi um script PHP que realiza o Download, tratamento e importação dessas informações CNL para uma base de dados MySQL.

Sendo assim o primeiro passo é criarmos as tabelas na base de dados no MySQL utilizando o script abaixo. Como o objetivo deste post não é ensinar como utilizar o MySQL entende-se que você detém este conhecimento e sabe como executar este script dentro da sua base de dados existente.

```sql
-- Criando estrutura para tabela cnl
CREATE TABLE IF NOT EXISTS `cnl` (
  `cod_cnl` int(11) NOT NULL,
  `cod_cnl_local` int(11) NOT NULL DEFAULT '0',
  `sigla_cnl` varchar(5) NOT NULL,
  `uf` varchar(2) NOT NULL,
  `ddd` varchar(2) NOT NULL,
  `localidade` varchar(200) NOT NULL,
  `municipio` varchar(200) NOT NULL,
  PRIMARY KEY (`cod_cnl`),
  UNIQUE KEY `sigla_cnl` (`sigla_cnl`)
)COLLATE='utf8_general_ci';

-- Criando estrutura para tabela cnl_tarifacao
CREATE TABLE IF NOT EXISTS `cnl_tarifacao` (
  `cod_cnl` int(11) NOT NULL,
  `cod_area_tarifacao` varchar(5) NOT NULL,
  `ddd` varchar(2) NOT NULL,
  `prefixo` varchar(5) NOT NULL,
  `prestadora` varchar(60) NOT NULL,
  `faixa_inicial` int(11) NOT NULL,
  `faixa_final` int(11) NOT NULL,
  PRIMARY KEY (`cod_cnl`,`ddd`,`prefixo`,`faixa_inicial`,`faixa_final`),
  KEY `ddd_prefixo` (`ddd`,`prefixo`),
  CONSTRAINT `FK_cnl_tarifacao_cnl` FOREIGN KEY (`cod_cnl`) REFERENCES `cnl` (`cod_cnl`) ON DELETE CASCADE ON UPDATE CASCADE
)COLLATE='utf8_general_ci';
```

Agora que criamos as tabelas na base de dados vamos criar o script PHP que irá realizar o download e importação dos dados. Copie o conteúdo abaixo em um script PHP (em nosso exemplo colocarei em **/usr/local/bin/importacnl.php**).

```php
#!/usr/bin/php -q
<?php
//-------------------------------------------------------------------+
// Autor        : Helvio Junior (helvio_junior@hotmail.com)          |
// Data         : 2016-06-02                                         |
// Atualizado   : 2017-09-30                                         |
// Versão       : 1.2                                                |
// Finalidade   : Realizar download e tratamento                     |
//                da base CNL para o MySQL                           |
//                                                                   |
// Atualizacoes : * Incluido checagem da config do FreePBX           |
//                * Corrigido BUG de parse do PHP 5.3                |
//-------------------------------------------------------------------+

//================ < Variaveis > ===================================
$dbhost='127.0.0.1';
$dbname='cnldb';
$dbuser='root';
$dbpass='cnlpwd';
$freepbx_configfile='/etc/amportal.conf';

//================ < Funções > ===================================

// Funcao utilizada em caso do servidor ser um FreePBX, para carregas as configs do mesmo
function parse_amportal_conf($filename) {
	$conf = array();

	/* defaults
	* This defines defaults and formatting to assure consistency across the system so that
	* components don't have to keep being 'gun shy' about these variables.
	*
	* we will read these settings out of the db, but only when $filename is writeable
	* otherwise, we read the $filename
	*/
	// If conf file is not writable, then we use it as the master so parse it.
	$file = file($filename);
	if (is_array($file)) {
			$write_back = false;
			foreach ($file as $line) {
					if (preg_match("/^\s*([a-zA-Z0-9_]+)=([a-zA-Z0-9 .&-@=_!<>\"\']+)\s*$/",$line,$matches)) {
							// overrite anything that was initialized from the db with the conf file authoritative source
							// if different from the db value then let's write it back to the db
							// TODO: massage any data we read from the conf file with _preapre_conf_value since it is
							//       written back to the DB here if different from the DB.
							//
							if (!isset($conf[$matches[1]]) || $conf[$matches[1]] != $matches[2]) {
								$conf[$matches[1]] = $matches[2];
							}
					}
			 }
	} else {
			die_freepbx(sprintf(_("Missing or unreadable config file [%s]...cannot continue"), $filename));
	}
	// Need to handle transitionary period where modules are adding new settings. So once we parsed the file
	// we still go read from the database and add anything that isn't there from the conf file.
	//

	$convert = array(
			'astetcdir'    => 'ASTETCDIR',
			'astmoddir'    => 'ASTMODDIR',
			'astvarlibdir' => 'ASTVARLIBDIR',
			'astagidir'    => 'ASTAGIDIR',
			'astspooldir'  => 'ASTSPOOLDIR',
			'astrundir'    => 'ASTRUNDIR',
			'astlogdir'    => 'ASTLOGDIR'
	);

	$file = file($conf['ASTETCDIR'].'/asterisk.conf');
	foreach ($file as $line) {
			if (preg_match("/^\s*([a-zA-Z0-9]+)\s* => \s*(.*)\s*([;#].*)?/",$line,$matches)) {
					$this->asterisk_conf[ $matches[1] ] = rtrim($matches[2],"/ \t");
			}
	}

	// Now that we parsed asterisk.conf, we need to make sure $amp_conf is consistent
	// so just set it to what we found, since this is what asterisk will use anyhow.
	//
	foreach ($convert as $ast_conf_key => $amp_conf_key) {
			if (isset($conf[$ast_conf_key])) {
					$conf[$amp_conf_key] = $this->asterisk_conf[$ast_conf_key];
			}
	}

	return $conf;
}

//Função responsável por realizar o explode da linha em uma array
function pc_fixed_width_substr($fields,$data) {
    $r = array();
    $line_pos = 0;
    foreach($fields as $field_name => $field_length) {
      //Identifica se os primeiros caracteres são espaço
      $tmp_data = substr($data,$line_pos,$field_length);
      if (strlen($tmp_data) != strlen(ltrim($tmp_data)))
          $line_pos += strlen($tmp_data) - strlen(ltrim($tmp_data));
      $r[$field_name] = utf8_encode(trim(substr($data,$line_pos,$field_length)));
      $line_pos += $field_length;
    }

  return $r;
}

//Em caso do servidor ser um FreePbx, carrega as informações do DB com base na config do FreePBX
if (file_exists($freepbx_configfile)){}
	$amp_conf = parse_amportal_conf($freepbx_configfile);

	$dbhost=$amp_conf['AMPDBHOST'];
	$dbname=$amp_conf['AMPDBNAME'];
	$dbuser=$amp_conf['AMPDBUSER'];
	$dbpass=$amp_conf['AMPDBPASS'];
}

//================ < Inicio > =====================================

$info = pathinfo(__FILE__);
openlog($info['basename'], LOG_PID | LOG_PERROR, LOG_LOCAL0);

date_default_timezone_set('America/Sao_Paulo');

//Cria a conexão com a base de dados
$conn = new PDO("mysql:host=$dbhost;dbname=$dbname;charset=utf8", $dbuser, $dbpass);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

//Realiza o download do arquivo da Anatel
echo "Realizando download do arquivo (Telefone Fixo)...\n";
$filename='/tmp/anatel-'.date("YmdHis").'.zip';
$filename2='/tmp/anatel-'.date("YmdHis").'.txt';
$filename3='/tmp/anatel-'.date("YmdHis").'-converted.txt';

$options = array(
        CURLOPT_RETURNTRANSFER => true,     // return web page
        CURLOPT_HEADER         => false,    // do not return headers
        CURLOPT_FOLLOWLOCATION => true,     // follow redirects
        CURLOPT_USERAGENT      => "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0", // who am i
        CURLOPT_AUTOREFERER    => true,     // set referer on redirect
        CURLOPT_CONNECTTIMEOUT => 120,      // timeout on connect
        CURLOPT_TIMEOUT        => 120,      // timeout on response
        CURLOPT_MAXREDIRS      => 10,       // stop after 10 redirects
        CURLOPT_POST           => true,         // POST
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_URL            => 'https://sistemas.anatel.gov.br/areaarea/N_Download/Tela.asp',
        CURLOPT_POSTFIELDS     => 'varTIPO=CentralCNL&varPRESTADORA=&varCENTRAL=F&varUF=&varPERIODO=&acao=c&cmd=&varMOD=Publico',
        CURLOPT_HTTPHEADER     => array(
                        'Content-type: application/x-www-form-urlencoded',
                        'Expect:'
                )
);

$ch      = curl_init( );
curl_setopt_array( $ch, $options );
$content = curl_exec( $ch );
$err     = curl_errno( $ch );
$errmsg  = curl_error( $ch );

curl_close( $ch );

$zipFile = fopen($filename, "w") or die("Unable to open file!");
fwrite($zipFile, $content);
fclose($zipFile);

if (!file_exists($filename)) die("Erro realizando download do arquivo");

//Descompacta o arquivo texto com os dados
echo "Descompactando arquivo...\n";
$zip = new ZipArchive;
if ($zip->open($filename) === true) {
    for($i = 0; $i < $zip->numFiles; $i++) {
        $file = $zip->getNameIndex($i);
        $fileinfo = pathinfo($file);
        if (strcasecmp($fileinfo['extension'], "txt") == 0) {
            copy("zip://".$filename."#".$file, $filename2);
        }

    }
    $zip->close();
}

//Processa o arquivo
if (!file_exists($filename2)) die("Erro descompactando o arquivo");

$fields = array('uf' => 2,
             'sigla_cnl' => 4,
             'cod_cnl' => 5,
             'localidade' => 50,
             'municipio' => 50,
             'cod_area_tarifacao' => 5,
             'ddd' => 2,
             'prefixo' => 5,
             'prestadora' => 30,
             'faixa_inicial' => 4,
             'faixa_final' => 4,
             'latitude' => 8,
             'hemisferio' => 5,
             'longitude' => 8,
             'cnl_local' => 4);

//Converte o arquivo
echo "Convertendo arquivo...\n";
exec("iconv -f iso-8859-1 -t UTF-8 $filename2 | sed 'y/áÁàÀãÃâÂéÉêÊíÍóÓõÕôÔúÚçÇ/aAaAaAaAeEeEiIoOoOoOuUcC/' > $filename3");

//Processa o arquivo
if (!file_exists($filename3)) die("Erro convertendo o arquivo");

//Realiza a primeira leitura do arquivo, para cadastrar todos os CNLs
//Depois realizará uma segunda leitura para cadastrar as tarifas
//Isso é necessário pois na tarida existe vínculo com o CNL da área
echo "Inserindo CNL...\n";
$handle = fopen($filename3, "r");
if ($handle) {
    while (($line = fgets($handle)) !== false) {

        //$line = trim(mb_convert_encoding($line, "UTF-8", "Windows-1252"));
        $line = trim($line);
        $data = pc_fixed_width_substr($fields,$line);

        //Executa a inserção
        try{
            $stmt = $conn->prepare( "INSERT INTO cnl (`cod_cnl`, `sigla_cnl`, `uf`, `ddd`, `localidade`, `municipio`) VALUES(:cod_cnl, :sigla_cnl, :uf, :ddd, :localidade, :municipio) ON DUPLICATE KEY UPDATE uf=VALUES(uf), ddd=VALUES(ddd), localidade=VALUES(localidade), municipio=VALUES(municipio)" );
            $stmt->bindValue(':cod_cnl', $data['cod_cnl']);
            $stmt->bindValue(':sigla_cnl', $data['sigla_cnl']);
            $stmt->bindValue(':uf', $data['uf']);
            $stmt->bindValue(':ddd', $data['ddd']);
            $stmt->bindValue(':localidade', $data['localidade']);
            $stmt->bindValue(':municipio', $data['municipio']);
            $stmt->execute();

            $stmt = $conn->prepare( "INSERT INTO cnl_tarifacao (`cod_cnl`, `cod_area_tarifacao`, `ddd`, `prefixo`, `prestadora`, `faixa_inicial`, `faixa_final`) VALUES(:cod_cnl, :cod_area_tarifacao, :ddd, :prefixo, :prestadora, :faixa_inicial, :faixa_final)  ON DUPLICATE KEY UPDATE cod_area_tarifacao=VALUES(cod_area_tarifacao),prestadora=VALUES(prestadora)" );
            $stmt->bindValue(':cod_cnl', $data['cod_cnl']);
            $stmt->bindValue(':cod_area_tarifacao', $data['cod_area_tarifacao']);
            $stmt->bindValue(':ddd', $data['ddd']);
            $stmt->bindValue(':prefixo', $data['prefixo']);
            $stmt->bindValue(':prestadora', substr($data['prestadora'],0,50));
            $stmt->bindValue(':faixa_inicial', intval($data['faixa_inicial']));
            $stmt->bindValue(':faixa_final', intval($data['faixa_final']));
            $stmt->execute();

        } catch (Exception $ex) {
            syslog(LOG_SYSLOG, "Erro na linha $line: ". $ex->getMessage());
            $debug = var_export($data, true);
            syslog(LOG_SYSLOG, $debug);
            die("Erro na linha $line: ". $ex->getMessage());
        }

        if (empty($data['ddd'])){
            var_dump($line);
            var_dump($data);
            die();
        }

    }

    fclose($handle);
} else {
    syslog(LOG_SYSLOG,"Erro abrindo o arquivo");
    die("Erro abrindo o arquivo");
}

//Realiza a releitura do arquivo
//Para atualizar a hierarquia de CNL
echo "Atualizando hierarquia de CNL, Passo 1...\n";
$handle = fopen($filename3, "r");
if ($handle) {
    while (($line = fgets($handle)) !== false)
    {

        //$line = trim(mb_convert_encoding($line, "UTF-8", "Windows-1252"));
        $line = trim($line);
        $data = pc_fixed_width_substr($fields,$line);
        $cod_cnl_local = -1;

        //Resgata o cód da CNL local
        //Em diversos casos a informação 'CNL local' vem em branco
        //estes casos serão tratados no passo 2
        if (!empty($data['cnl_local']))
        {
            $stmt = $conn->prepare('SELECT cod_cnl from cnl WHERE sigla_cnl = :sigla_cnl');
            $stmt->bindValue(':sigla_cnl', $data['cnl_local']);
            $stmt->execute();

            if ($row = $stmt->fetch(PDO::FETCH_ASSOC)){
                $cod_cnl_local = $row["cod_cnl"];
            }
        }

        if ($cod_cnl_local != -1){
            try{

                $stmt = $conn->prepare( "UPDATE cnl SET cod_cnl_local = :cod_cnl_local where cod_cnl = :cod_cnl" );
                $stmt->bindValue(':cod_cnl', $data['cod_cnl']);
                $stmt->bindValue(':cod_cnl_local', $cod_cnl_local);
                $stmt->execute();

            } catch (Exception $ex) {
                syslog(LOG_SYSLOG, "Erro na linha $line: ". $ex->getMessage());
                $debug = var_export($data, true);
                syslog(LOG_SYSLOG, $debug);
                die("Erro na linha $line: ". $ex->getMessage());
            }
        }

    }

    fclose($handle);
} else {
    syslog(LOG_SYSLOG, "Erro na linha $line: ". $ex->getMessage());
    die("Erro abrindo o arquivo");
}

//Realiza a releitura do arquivo
//Para atualizar a hierarquia de CNL
echo "Atualizando hierarquia de CNL, Passo 2...\n";
try{
    $stmt = $conn->prepare( "select * from cnl where cod_cnl_local = 0" );
    $stmt->execute();

    while ($row = $stmt->fetch(PDO::FETCH_ASSOC))
    {
        $cod_cnl_local = -1;
        $track = "";
        $ddd = $row['ddd'];

        //Resgata o cód da CNL local
        //Em diversos casos a informação 'CNL local' vem em branco
        //Nestes casos verificar qual é a CNL mais expressiva a partir do DDD e usa-la
        if (!empty($data['cnl_local']))
            continue;

        //Em diversos casos a informação 'CNL local' vem em branco
        //Nestes casos verificar qual é a CNL mais expressiva a partir do DDD e usa-la
        $track = "$track cnl = -1\n";

        $s1 = $conn->prepare('select * ,(select count(*) from cnl c1 where c1.cod_cnl_local = c.cod_cnl) as `chields` from cnl c where c.cod_cnl != c.cod_cnl_local and ddd = :ddd order by c.ddd, 8 desc limit 1');
        $s1->bindValue(':ddd', $ddd);
        $s1->execute();

        $debug = var_export($s1, true);
        $track = "$track $debug\n";

        $track = "$track :ddd = $ddd\n";

        $r1 = $s1->fetch(PDO::FETCH_ASSOC);

        $debug = var_export($r1, true);
        $track = "$track $debug\n";

        if ($r1){
            $cod_cnl_local = $r1["cod_cnl"];
            $track = "$track cod_cnl = $cod_cnl_local\n";
        }

        if ($cod_cnl_local != -1){
            try{

                $s1 = $conn->prepare( "UPDATE cnl SET cod_cnl_local = :cod_cnl_local where cod_cnl = :cod_cnl" );
                $s1->bindValue(':cod_cnl', $row['cod_cnl']);
                $s1->bindValue(':cod_cnl_local', $cod_cnl_local);
                $s1->execute();

            } catch (Exception $ex) {
                syslog(LOG_SYSLOG, "Erro na linha $line: ". $ex->getMessage());
                $debug = var_export($row, true);
                syslog(LOG_SYSLOG, $debug);
                die("Erro na linha $line: ". $ex->getMessage());
            }
        }else{
            $debug = var_export($row, true);
            syslog(LOG_SYSLOG, "CNL Local não identificado: $track $debug");
        }

    }

} catch (Exception $ex) {
    syslog(LOG_SYSLOG, "Erro processando: ". $ex->getMessage());
    die();
}

//Exclui os arquivos
echo "Excluindo arquivos temporários...\n";
unlink($filename3);
unlink($filename2);
unlink($filename);

closelog();
//================ < Fim >====================================
```

Edite as variáveis ($dbhost, $dbname, $dbuser e $dbpass) para representar as informações do seu ambiente. Execute o comando abaixo para liberar execução deste arquivo.

Obs.: Em caso de utilização no FreePBX, não se faz necessário editar as variáveis ($dbhost, $dbname, $dbuser e $dbpass), pois o script resgata essas informações automaticamente da configuração do seu FreePBX.

```bash
 chmod +x /usr/local/bin/importacnl.php
```

Por fim execute o script para realizar a importação. E aproveite para dar uma navegada em outros posts aqui do site, curta, compartilhe, ou quem sabe vá tomar um café, energético, suco, ler um livro, pois este processo deve demorar alguns minutos para executar.

[![asterisk_cnl_003]({{ site.baseurl }}/assets/2016/07/asterisk_cnl_003.png)]({{ site.baseurl }}/assets/2016/07/asterisk_cnl_003.png)

O interessante é colocar este script para executar uma vez por semana (usando crontab), para manter essa base sempre atualizada.

## Configurando o asterisk

*** ATENÇÃO!!! Em caso de utilização em FreePBX, recomendo utilizar o script específico para ele que se encontra mais abaixo neste post.

Enfim chegamos ao asterisk, nesta sessão iremos criar o nosso script AGI bem como configurar nosso plano de discagem do asterisk para consultar essa base de dados e decidir se devemos ou não inserir o DDD nas ligações.

Para nosso script AGI utilizaremos a biblioteca PHPAGI disponível em ([http://phpagi.sourceforge.net/](http://phpagi.sourceforge.net/)), mas pode ficar despreocupado colocarei aqui um arquivo zip com todo o conteúdo do AGI + a biblioteca phpagi.

Crie um arquivo **/var/lib/asterisk/agi-bin/consultacnl.php** com o conteúdo abaixo

```bash
#!/usr/bin/php -q
<?php
//-----------------------------------------------------------------+
// Autor      : Helvio Junior (helvio_junior@hotmail.com)          |
// Data       : 2016-06-02                                         |
// Versão     : 1.0                                                |
// Finalidade : Consulta a base CNL                                |
//-----------------------------------------------------------------+

//================ < Includes > ===================================
require_once __DIR__.'/phpagi-2.20/phpagi.php';

//================ < Variaveis > ===================================
$dbhost='127.0.0.1';
$dbname='cnldb';
$dbuser='cnluser';
$dbpass='cnlpwd';

//================ < Inicio > =====================================
$agi = new AGI();

$exten = '';

$uniqueId = $agi->request['agi_uniqueid'];

if ((isset($agi->request['agi_extension'])) && ($agi->request['agi_extension'] != ''))
	$exten = $agi->request['agi_extension'];

if (empty($uniqueId) || empty($exten))
{
	$agi->exec('VERBOSE','"Exten não fornecidos" 3');
	die();
}

try{

	$ddd=substr($exten,0,2);
	$prefixo=substr($exten,2,4);
	$sufixo=substr($exten,6,4);

	$agi->exec('VERBOSE','"Consultando CNL para '.$exten.' ('.$ddd.') '.$prefixo.'-'.$sufixo.'" 4');

	//Cria a conexão com a base de dados
	$conn = new PDO("mysql:host=$dbhost;dbname=$dbname;charset=utf8", $dbuser, $dbpass);
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	$stmt = $conn->prepare('select p.* from cnl c inner join cnl_tarifacao t on c.cod_cnl = t.cod_cnl inner join cnl p on c.cod_cnl_local = p.cod_cnl where t.ddd = :ddd and t.prefixo = :prefixo and :sufixo between t.faixa_inicial and t.faixa_final');
	$stmt->bindValue(':ddd', $ddd);
	$stmt->bindValue(':prefixo', $prefixo);
	$stmt->bindValue(':sufixo', $sufixo);
	$stmt->execute();

	$cnl="";
	if ($row = $stmt->fetch(PDO::FETCH_ASSOC)){
		$cnl = $row["sigla_cnl"];
		$agi->exec('VERBOSE','"CNL encontrado para '.$exten.' -> '.$cnl.'" 4');
	}

	//Define o cnl
	$agi->exec('SET',"cnl=$cnl");

    return 0;

} catch (Exception $e) {
    $agi->exec("NOOP", '"'.$e->getMessage().'"');
}
```

Igualmente ao script anterior edite as variáveis ($dbhost, $dbname, $dbuser e $dbpass) para representar as informações do seu ambiente.

Ajuste a permissão de execução do seu script

```bash
 chmod +x /var/lib/asterisk/agi-bin/consultacnl.php
```

No arquivo **/etc/asterisk/extensions.conf** edite o seu contexto da ligação conforme o exemplo abaixo

```bash
[trunk_out]
; Local
exten = _XXXXXXXX,1,Goto(041${EXTEN},1)
; LDN
exten = _0ZZ[2-6]XXXXXXX,1,Goto(${EXTEN:1},1)
exten = _0ZZ[2-6]XXXXXXXX,1,Goto(${EXTEN:1},1)

;Normalizado
exten = _ZZXXXXXXX.,1,AGI(consultacnl.php)
exten = _ZZXXXXXXX.,n,ExecIf($["${cnl}" = "CTA"]?Set(number=${EXTEN:2}))
exten = _ZZXXXXXXX.,n,Dial(SIP/trunk_sip/${number},90,TtXx)
```

Lembrando que neste exemplo considero como origem da ligação o DDD 41 e CNL CTA.

## Configurando o FreePBX

*** ATENÇÃO!!! Este script foi desenvolvido para utilização no padrão do FreePBX, em caso de utilização em outra plataforma, pode ser necessário realização de alterações.

Enfim chegamos ao FreePBX, nesta sessão iremos criar o nosso script AGI bem como configurar nosso plano de discagem do FreePBX para consultar essa base de dados e decidir se devemos ou não inserir/excluir o DDD nas ligações.

Para nosso script AGI utilizaremos a biblioteca PHPAGI disponível em ([http://phpagi.sourceforge.net/](http://phpagi.sourceforge.net/)), mas pode ficar despreocupado colocarei aqui um arquivo zip com todo o conteúdo do AGI + a biblioteca phpagi.

Crie um arquivo **/var/lib/asterisk/agi-bin/alteracnl.php** com o conteúdo abaixo

```bash
#!/usr/bin/php -q
<?php
//--------------------------------------------------------------------+
// Autor      : Helvio Junior (helvio_junior@hotmail.com)             |
// Data       : 2016-06-02                                            |
// Atualizado : 2017-09-30                                            |
// Versão     : 1.2                                                   |
// Finalidade : Consulta a base CNL e corrige o numero para FreePBX   |
//              *** Utilizar este script preferencialmente no FreePBX |
//--------------------------------------------------------------------+

//================ < Includes > ===================================
require_once __DIR__.'/phpagi-2.20/phpagi.php';

//================ < Variaveis > ===================================
$configfile='/etc/amportal.conf';

//================ < Funções > ===================================

function parse_amportal_conf($filename) {
	$conf = array();

	/* defaults
	* This defines defaults and formatting to assure consistency across the system so that
	* components don't have to keep being 'gun shy' about these variables.
	*
	* we will read these settings out of the db, but only when $filename is writeable
	* otherwise, we read the $filename
	*/
	// If conf file is not writable, then we use it as the master so parse it.
	$file = file($filename);
	if (is_array($file)) {
			$write_back = false;
			foreach ($file as $line) {
					if (preg_match("/^\s*([a-zA-Z0-9_]+)=([a-zA-Z0-9 .&-@=_!<>\"\']+)\s*$/",$line,$matches)) {
							// overrite anything that was initialized from the db with the conf file authoritative source
							// if different from the db value then let's write it back to the db
							// TODO: massage any data we read from the conf file with _preapre_conf_value since it is
							//       written back to the DB here if different from the DB.
							//
							if (!isset($conf[$matches[1]]) || $conf[$matches[1]] != $matches[2]) {
								$conf[$matches[1]] = $matches[2];
							}
					}
			 }
	} else {
			die_freepbx(sprintf(_("Missing or unreadable config file [%s]...cannot continue"), $filename));
	}
	// Need to handle transitionary period where modules are adding new settings. So once we parsed the file
	// we still go read from the database and add anything that isn't there from the conf file.
	//

	$convert = array(
			'astetcdir'    => 'ASTETCDIR',
			'astmoddir'    => 'ASTMODDIR',
			'astvarlibdir' => 'ASTVARLIBDIR',
			'astagidir'    => 'ASTAGIDIR',
			'astspooldir'  => 'ASTSPOOLDIR',
			'astrundir'    => 'ASTRUNDIR',
			'astlogdir'    => 'ASTLOGDIR'
	);

	$file = file($conf['ASTETCDIR'].'/asterisk.conf');
	foreach ($file as $line) {
			if (preg_match("/^\s*([a-zA-Z0-9]+)\s* => \s*(.*)\s*([;#].*)?/",$line,$matches)) {
					$this->asterisk_conf[ $matches[1] ] = rtrim($matches[2],"/ \t");
			}
	}

	// Now that we parsed asterisk.conf, we need to make sure $amp_conf is consistent
	// so just set it to what we found, since this is what asterisk will use anyhow.
	//
	foreach ($convert as $ast_conf_key => $amp_conf_key) {
			if (isset($conf[$ast_conf_key])) {
					$conf[$amp_conf_key] = $this->asterisk_conf[$ast_conf_key];
			}
	}

	return $conf;
}

//Carrega as informações do DB com base na config do FrePBX
$amp_conf = parse_amportal_conf($configfile);

$dbhost=$amp_conf['AMPDBHOST'];
$dbname=$amp_conf['AMPDBNAME'];
$dbuser=$amp_conf['AMPDBUSER'];
$dbpass=$amp_conf['AMPDBPASS'];

//================ < Inicio > =====================================
$agi = new AGI();

$dialnumber = '';

$uniqueId = $agi->request['agi_uniqueid'];

$dialnumber = '';
$cnllocal = '';

$tmp = $agi->get_variable("OUTNUM");
if (isset($tmp['data']) && !empty($tmp['data'])){
		$dialnumber = $tmp['data'];
}

$tmp = $agi->get_variable("agi_arg_1");
if (isset($agi->request['agi_arg_1']) && !empty($agi->request['agi_arg_1'])){
		$cnllocal = $agi->request['agi_arg_1'];
}

if (empty($uniqueId) || empty($dialnumber) || empty($cnllocal))
{
    $agi->exec('VERBOSE','"DialNumber e CNL Local não fornecidos" 3');
    die();
}

try{

    //Cria a conexão com a base de dados
    $conn = new PDO("mysql:host=$dbhost;dbname=$dbname;charset=utf8", $dbuser, $dbpass);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	//Em caso do numero discado ter 8 digitos
	//Inclui o DDD da mesma CNL do usuário, para posteriormente checar se os numeros fazem parte da mesma CNL
	//Pois o usuário intuitivamente não digita o numero com DDD quando é o mesmo DDD que ele faz parte
	if (strlen($dialnumber) == 8){

		$stmt = $conn->prepare('select c.* from cnl c where c.sigla_cnl = :sigla_cnl');
		$stmt->bindValue(':sigla_cnl', $cnllocal);
		$stmt->execute();
		if ($row = $stmt->fetch(PDO::FETCH_ASSOC)){
			$ddd = $row["ddd"];

			$old = $dialnumber;
			$dialnumber = $ddd . $dialnumber;
			$agi->exec('VERBOSE','"Numero com 8 digitos. Incluindo DDD para consulta. Old: '.$old.' New: '.$dialnumber.'" 4');

			$agi->exec('SET','OUTNUM=0'.$dialnumber);
			$agi->exec('SET','DIAL_NUMBER=0'.$dialnumber);
		}

	}

	//Remove o "zero" como primeiro digito, caso seja
	if (substr($dialnumber,0,1) == '0')
		$dialnumber = substr($dialnumber,1);

    $ddd=substr($dialnumber,0,2);
    $prefixo=substr($dialnumber,2,4);
    $sufixo=substr($dialnumber,6,4);

    $agi->exec('VERBOSE','"Consultando CNL para '.$dialnumber.' ('.$ddd.') '.$prefixo.'-'.$sufixo.'" 4');

    $stmt = $conn->prepare('select p.* from cnl c inner join cnl_tarifacao t on c.cod_cnl = t.cod_cnl inner join cnl p on c.cod_cnl_local = p.cod_cnl where t.ddd = :ddd and t.prefixo = :prefixo and :sufixo between t.faixa_inicial and t.faixa_final');
    $stmt->bindValue(':ddd', $ddd);
    $stmt->bindValue(':prefixo', $prefixo);
    $stmt->bindValue(':sufixo', $sufixo);
    $stmt->execute();

    $cnl="";
    if ($row = $stmt->fetch(PDO::FETCH_ASSOC)){
        $cnl = $row["sigla_cnl"];
        $agi->exec('VERBOSE','"CNL encontrado para '.$dialnumber.' -> '.$cnl.'" 4');
    }

    //Caso seja o mesmo CNL, remove o DDD do número a ser discado
	if ($cnllocal == $cnl){
		$agi->exec('SET','OUTNUM='.$prefixo.$sufixo);
		$agi->exec('SET','DIAL_NUMBER='.$prefixo.$sufixo);
	}

    return 0;

} catch (Exception $e) {
    $agi->exec("NOOP", '"'.$e->getMessage().'"');
}
```

Neste script não se faz necessário alterar as variáveis ($dbhost, $dbname, $dbuser e $dbpass) pois o script pega as informações da configuração do seu FreePBX.

Ajuste a permissão de execução do seu script

```bash
 chmod +x /var/lib/asterisk/agi-bin/alteracnl.php
```

No arquivo **/etc/asterisk/extensions_custom.conf** edite o seu contexto da ligação conforme o exemplo abaixo

```bash
[macro-dialout-trunk-predial-hook]
exten => s,1,Agi(alteracnl.php,CTA)
```

Lembrando que neste exemplo considero como origem da ligação o DDD 41 e CNL CTA.

## Considerações finais

Segue o link ([CNL]({{ site.baseurl }}/assets/2016/07/CNL1.zip)) para download do zip com todos os arquivos deste ambiente.

Espero ter ajudado. Caso tenha dúvidas, sugestões fique a vontade para comentar, mandar e-mail e etc...
