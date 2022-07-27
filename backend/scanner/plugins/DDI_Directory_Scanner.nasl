###############################################################################
# OpenVAS Vulnerability Test
# $Id: DDI_Directory_Scanner.nasl 13713 2019-02-16 19:41:25Z cfischer $
#
# Directory Scanner
#
# Authors:
# H D Moore <hdm@digitaloffense.net>
#
# Copyright:
# Copyright (C) 2005 Digital Defense Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11032");
  script_version("2019-04-05T11:40:39+0000");
  script_tag(name:"last_modification", value:"2019-04-05 11:40:39 +0000 (Fri, 05 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Directory Scanner");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Digital Defense Inc.");
  script_family("Service detection");
  # Don't add http_version.nasl which has a dependency to this NVT
  script_dependencies("find_service.nasl", "httpver.nasl", "embedded_web_server_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_timeout(900);

  script_tag(name:"summary", value:"This plugin attempts to determine the presence of various
  common dirs on the remote web server");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("404.inc"); # For errmessages_404 list
include("misc_func.inc");

debug = 0;

# this arrays contains the results
discoveredDirList = make_list();
authDirList = make_list();

cgi_dirs_exclude_pattern = get_kb_item( "global_settings/cgi_dirs_exclude_pattern" );
use_cgi_dirs_exclude_pattern = get_kb_item( "global_settings/use_cgi_dirs_exclude_pattern" );
cgi_dirs_exclude_servermanual = get_kb_item( "global_settings/cgi_dirs_exclude_servermanual" );

function check_cgi_dir( dir, port ) {

  local_var req, res, dir, port;

  req = http_get( item:dir + "/non-existent"  + rand(), port:port );
  res = http_keepalive_send_recv( data:req, port:port, bodyonly:FALSE );
  if( isnull( res ) ) failedReqs++;

  if( res =~ "^HTTP/1\.[01] 404" ) {
    return TRUE;
  } else {
    return FALSE;
  }
}

function add_discovered_list( dir, port, host ) {

  local_var dir, port, host, dir_key;

  if( ! in_array( search:dir, array:discoveredDirList ) ) {
    discoveredDirList = make_list( discoveredDirList, dir );

    if( use_cgi_dirs_exclude_pattern ) {
      if( egrep( pattern:cgi_dirs_exclude_pattern, string:dir ) ) {
        set_kb_item( name:"www/" + host + "/" + port + "/content/excluded_directories", value:dir );
        return;
      }
    }

    #TBD: Do a check_cgi_dir( dir:dir, port:port ); before?
    dir_key = "www/" + host + "/" + port + "/content/directories";
    if( debug ) display( "Setting KB key: ", dir_key, " to '", dir, "'\n" );
    set_kb_item( name:dir_key, value:dir );
  }
}

function add_auth_dir_list( dir, port, host, basic, realm ) {

  local_var dir, port, host, dir_key, basic, realm;

  if( ! in_array( search:dir, array:authDirList ) ) {

    authDirList = make_list( authDirList, dir );

    if( use_cgi_dirs_exclude_pattern ) {
      if( egrep( pattern:cgi_dirs_exclude_pattern, string:dir ) ) {
        set_kb_item( name:"www/" + host + "/" + port + "/content/excluded_directories", value:dir );
        return;
      }
    }

    set_kb_item( name:"www/content/auth_required", value:TRUE );
    dir_key = "www/" + host + "/" + port + "/content/auth_required";
    if( debug ) display( "Setting KB key: ", dir_key, " to '", dir, "'\n" );
    set_kb_item( name:dir_key, value:dir );

    # Used in 2018/gb_http_cleartext_creds_submit.nasl
    if( basic ) {
      set_kb_item( name:"www/basic_auth/detected", value:TRUE );
      set_kb_item( name:"www/pw_input_field_or_basic_auth/detected", value:TRUE );
      # Used in 2018/gb_http_cleartext_creds_submit.nasl
      set_kb_item( name:"www/" + host + "/" + port + "/content/basic_auth/" + dir, value:report_vuln_url( port:port, url:dir, url_only:TRUE ) + ":" + realm );
    }
  }
}

# TODO: Update list with directories
testDirList = make_list(
".cobalt",
# https://ma.ttias.be/well-known-directory-webservers-aka-rfc-5785/
# https://tools.ietf.org/html/rfc5785
# http://sabre.io/dav/service-discovery/
# https://github.com/owncloud/core/blob/29570212c983f0293738dbb0132a5b562dcac9fa/.htaccess#L66-L69
".well-known",
".well-known/acme-challenge",
".well-known/caldav",
".well-known/carddav",
".well-known/host-meta",
".well-known/pki-validation",
"1",
"10",
"2",
"3",
"4",
"5",
"6",
"7",
"8",
"9",
"AdminWeb",
"Admin_files",
"Administration",
"AdvWebAdmin",
"Agent",
"Agents",
"Album",
"AlbumArt_",
"BizTalkTracking",
"BizTalkServerDocs",
"BizTalkServerRepository",
"Boutiques",
"Corporate",
"CS",
"CVS",
"DB4Web",
"DMR",
"DocuColor",
"DVWA",
"GXApp",
"HB",
"HBTemplates",
"IBMWebAS",
"Install",
"JBookIt",
"Log",
"Mail",
"MessagingManager",
"Msword",
"NSearch",
"NetDynamic",
"NetDynamics",
"News",
"PDG_Cart",
"README",
"ROADS",
"Readme",
"Remote",
"SilverStream",
"Stats",
"StoreDB",
"Templates",
"ToDo",
"WebBank",
"WebCalendar",
"WebDB",
"WebShop",
"WebTrend",
"Web_store",
"WSsamples",
"XSL",
"_ScriptLibrary",
"_backup",
"_derived",
"_errors",
"_fpclass",
"_mem_bin",
"_notes",
"_objects",
"_old",
"_pages",
"_passwords",
"_private",
"_scripts",
"_sharedtemplates",
"_tests",
"_themes",
"_vti_bin",
"_vti_bot",
"_vti_log",
"_vti_pvt",
"_vti_shm",
"_vti_txt",
"a",
"about",
"acceso",
"access",
"accesswatch",
"acciones",
"account",
"accounting",
"activex",
"adm",
"admcgi",
"admentor",
"admin_",
"admin",
"admin.back",
"admin-bak",
"adminer",
"administration",
"administrator",
"admin-old",
"adminuser",
"adminweb",
"admisapi",
"agentes",
"analog",
"analytics",
"anthill",
"apache",
"api",
"app",
"applets",
"application",
"applications",
"apps",
"ar",
"archive",
"archives",
"asp",
"aspx",
"atc",
"auth",
"authadmin",
"aw",
"ayuda",
"b",
"b2-include",
"back",
"backend",
"backup",
"backups",
"bak",
"banca",
"banco",
"bank",
"banner",
"banner01",
"banners",
"batch",
"bb-dnbd",
"bbv",
"bdata",
"bdatos",
"beta",
"billpay",
"bin",
"blog",
"boadmin",
"board",
"boot",
"btauxdir",
"bug",
"bugs",
"bugzilla",
"business",
"buy",
"buynow",
"c",
"cache-stats",
"cacti",
"caja",
"card",
"cards",
"cart",
"cash",
"caspsamp",
"catalog",
"cbi-bin",
"ccard",
"ccards",
"cd",
"cd-cgi",
"cdrom",
"ce_html",
"cert",
"certificado",
"certificate",
"cfappman",
"cfdocs",
"cfide",
"cgi",
"cgi-auth",
"cgi-bin",
"cgibin",
"cgi-bin2",
"cgi-csc",
"cgi-lib",
"cgilib",
"cgi-local",
"cgis",
"cgi-scripts",
"cgiscripts",
"cgi-shl",
"cgi-shop",
"cgi-sys",
"cgi-weddico",
"cgi-win",
"cgiwin",
"chat",
"class",
"classes",
"client",
"cliente",
"clientes",
"cm",
"cmsample",
"cobalt-images",
"code",
"comments",
"common",
"communicator",
"community",
"company",
"compra",
"compras",
"compressed",
"conecta",
"conf",
"config",
"connect",
"console",
"content",
"controlpanel",
"core",
"corp",
"correo",
"counter",
"credit",
"cron",
"crons",
"crypto",
"csr",
"css",
"cuenta",
"cuentas",
"currency",
"customers",
"cvsweb",
"cybercash",
"d",
"darkportal",
"dashboard",
"dat",
"data",
"database",
"databases",
"datafiles",
"dato",
"datos",
"dav",
"db",
"dbase",
"dcforum",
"ddreport",
"ddrint",
"demo",
"demoauct",
"demomall",
"demos",
"design",
"dev",
"devel",
"development",
"dialup",
"dialup_admin",
"dir",
"directory",
"directorymanager",
"dl",
"dll",
"dm",
"dms",
"dms0",
"dmsdump",
"doc",
"doc1",
"doc-html",
"docs",
"docs1",
"document",
"documents",
"down",
"download",
"downloads",
"drupal",
"drupal7",
"dspam",
"dump",
"durep",
"e",
"easylog",
"eforum",
"egroupware",
"ejemplo",
"ejemplos",
"email",
"emailclass",
"eManager",
"employees",
"empoyees",
"empris",
"envia",
"enviamail",
"error",
"errors",
"es",
"estmt",
"etc",
"example",
"examples",
"exc",
"excel",
"exchange",
"exe",
"exec",
"export",
"external",
"f",
"fbsd",
"fcgi-bin",
"file",
"filemanager",
"files",
"flexcube@",
"flexcubeat",
"foldoc",
"form",
"forms",
"formsmgr",
"form-totaller",
"forum",
"forums",
"foto",
"fotos",
"fpadmin",
"fpdb",
"fpsample",
"frameset",
"framesets",
"ftp",
"ftproot",
"g",
"ganglia",
"gfx",
"global",
"gosa",
"grocery",
"guest",
"guestbook",
"guests",
"help",
"helpdesk",
"hidden",
"hide",
"hitmatic",
"hit_tracker",
"hlstats",
"home",
"horde",
"hostingcontroller",
"howto",
"ht",
"htbin",
"htdocs",
"html",
"hyperstat",
"ibank",
"ibill",
"icingaweb2",
"icons",
"idea",
"ideas",
"iisadmin",
"iisprotect",
"iissamples",
"ikiwiki",
"image",
"imagenes",
"imagery",
"images",
"img",
"imp",
"import",
"impreso",
"inc",
"include",
"includes",
"incoming",
"info",
"information",
"ingresa",
"ingreso",
"install",
"internal",
"intranet",
"inventory",
"invitado",
"isapi",
"japidoc",
"java",
"javascript",
"javasdk",
"javatest",
"jave",
"jdbc",
"job",
"jrun",
"js",
"jserv",
"jslib",
"jsp",
"junk",
"keyserver",
"kibana",
"kiva",
"labs",
"lam",
"lcgi",
"legal",
"lib",
"libraries",
"library",
"libro",
"links",
"linux",
"loader",
"log",
"logfile",
"logfiles",
"logg",
"logger",
"logging",
"login",
"logon",
"logs",
"lost+found",
"m",
"mail",
"mail_log_files",
"mailman",
"mailroot",
"makefile",
"mall_log_files",
"manage",
"manual",
"marketing",
"matomo",
"member",
"members",
"mercuryboard",
"message",
"messaging",
"metacart",
"misc",
"mkstats",
"movimientos",
"mp3",
"mp3s",
"mqseries",
"msql",
"myaccount",
"mysql",
"mysql_admin",
"ncadmin",
"nchelp",
"ncsample",
"nds",
"netbasic",
"netcat",
"netmagstats",
"netscape",
"netshare",
"nettracker",
"new",
"nextgeneration",
"nl",
"noticias",
"obj",
"objects",
"odbc",
"offers",
"ojs",
"old",
"old_files",
"oldfiles",
"oprocmgr-service",
"oprocmgr-status",
"oracle",
"oradata",
"order",
"orders",
"otrs",
"otrs-web",
"outgoing",
"owncloud",
"owners",
"pages",
"passport",
"password",
"passwords",
"payment",
"payments",
"pccsmysqladm",
"perl",
"perl5",
"personal",
"personal_pages",
"pforum",
"phorum",
"php",
"phpBB",
"php_classes",
"phpclassifieds",
"phpimageview",
"phpip",
"phpldapadmin",
"phpmyadmin",
"phpMyAdmin",
"phpnuke",
"phppgadmin",
"phpPhotoAlbum",
"phpprojekt",
"phpSecurePages",
"piranha",
"piwik",
"pls",
"pma",
"poll",
"polls",
"portal",
"postgres",
"ppwb",
"printers",
"priv",
"privado",
"private",
"prod",
"protected",
"prueba",
"pruebas",
"prv",
"pub",
"public",
"publica",
"publicar",
"publico",
"publish",
"purchase",
"purchases",
"pw",
"random_banner",
"rdp",
"redmine",
"register",
"registered",
"rem",
"report",
"reports",
"reseller",
"restricted",
"retail",
"reviews",
"root",
"roundcube",
"roundcubemail",
"rsrc",
"sales",
"sample",
"samples",
"save",
"script",
"scripts",
"search",
"search97",
"search-ui",
"secret",
"secure",
"secured",
"sell",
"serve",
"server-info",
"servers",
"server_stats",
"serverstats",
"server-status",
"service",
"services",
"servicio",
"servicios",
"servlet",
"servlets",
"session",
"setup",
"share",
"shared",
"shell-cgi",
"shipping",
"shop",
"shopper",
"shopping",
"site",
"siteadmin",
"sitebuildercontent",
"sitebuilderfiles",
"sitebuilderpictures",
"sitemgr",
"siteminder",
"siteminderagent",
"sites",
"siteserver",
"sitestats",
"siteupdate",
"slide",
"smreports",
"smreportsviewer",
"soap",
"soapdocs",
"software",
"solaris",
"solutions",
"source",
"sql",
"squid",
"squirrelmail",
"src",
"srchadm",
"ssi",
"ssl",
"ssp",
"sslkeys",
"staff",
"stag",
"stage",
"staging",
"stat",
"statistic",
"statistics",
"statistik",
"statistiken",
"stats",
"stats-bin-p",
"stats_old",
"status",
"storage",
"store",
"storemgr",
"stronghold-info",
"stronghold-status",
"stuff",
"style",
"styles",
"stylesheet",
"stylesheets",
"subir",
"sun",
"super_stats",
"support",
"supporter",
"sys",
"sysadmin",
"sysbackup",
"system",
"tar",
"tarantella",
"tarjetas",
"tdbin",
"tech",
"technote",
"te_html",
"temp",
"template",
"templates",
"temporal",
"test",
"test-cgi",
"testing",
"tests",
"testweb",
"ticket",
"tickets",
"tiki",
"tikiwiki",
"tmp",
"tools",
"tpv",
"trabajo",
"trac",
"track",
"tracking",
"transito",
"transpolar",
"tree",
"trees",
"twiki",
"ucs-overview",
"univention-management-console",
"updates",
"upload",
"uploads",
"us",
"usage",
"user",
"userdb",
"users",
"usr",
"ustats",
"usuario",
"usuarios",
"util",
"utils",
"v4",
"vfs",
"w3perl",
"w-agora",
"way-board",
"web",
"web800fo",
"webadmin",
"webalizer",
# <-- e.g. Zarafa
"webaccess",
"webapp",
# -->
"webapps",
"webboard",
"webcart",
"webcart-lite",
"webdata",
"webdav",
"webdb",
"webimages",
"webimages2",
"weblog",
"weblogs",
"webmail",
"webmaster",
"webmaster_logs",
"webMathematica",
"webpub",
"webpub-ui",
"webreports",
"webreps",
"webshare",
"website",
"webstat",
"webstats",
"webtrace",
"webtrends",
"web_usage",
"wiki",
"windows",
"word",
"wordpress",
"work",
"wp",
"wsdocs",
"wstats",
"wusage",
"www",
"wwwjoin",
"wwwlog",
"www-sql",
"wwwstat",
"wwwstats",
"xampp",
"xGB",
"xml",
"xtemp",
"zabbix",
"zb41",
"zipfiles",
"~1",
"~admin",
"~log",
"~root",
"~stats",
"~webstats",
"~wsdocs",
# The three following directories exist on Resin default installation
"faq",
"ref",
"cmp",
# Phishing
"cgi-bim",
# Lite-serve
"cgi-isapi",
# HyperWave
"wavemaster.internal",
# Urchin
"urchin",
"urchin3",
"urchin5",
# CVE-2000-0237
"publisher",
# Common Locale
"en",
"en-US",
"fr",
"intl",
# Sympa
"wws",
# Opentaps and Apache OFBiz
"accounting/control/main",
"ap/control/main",
"ar/control/main",
"assetmaint/control/main",
"bi/control/main",
"birt/control/main",
"catalog/control/main",
"content/control/main",
"crmsfa/control/main",
"ebay/control/main",
"ecommerce/control/main",
"ecomseo", # nb: special case
"example/control/main",
"exampleext/control/main",
"facility/control/main",
"financials/control/main",
"googlebase/control/main",
"hhfacility/control/main",
"humanres/control/main",
"manufacturing/control/main",
"marketing/control/main",
"myportal/control/main",
"ofbizsetup/control/main",
"ordermgr/control/main",
"partymgr/control/main",
"projectmgr/control/main",
"purchasing/control/main",
"scrum/control/main",
"sfa/control/main",
"solr/control/main",
"warehouse/control/main",
"webpos/control/main",
"webtools/control/main",
"workeffort/control/main",
# e.g. Metasploitable2 VM
"dvwa",
"mutillidae",
# ownCloud
"updater",
"ocs-provider",
"ocm-provider", #nb: OpenCloudMesh Endpoint
# Tomcat
"tomcat-docs", #nb: Will be ignored by default
"manager/html",
"host-manager/html",
"manager/status" );
#TODO: Fill the list with the directories used in the foreach( cgi_dirs ) loop of the Detection-NVTs

# Add domain name parts, create_hostname_parts_list() always returns a list, even an empty one
hnlist = create_hostname_parts_list();
testDirList = make_list( testDirList, hnlist );

if( debug ) display( "::[ DDI Directory Scanner running in debug mode\n::\n" );

fake404 = string("");
Check200 = TRUE;
Check401 = TRUE;
Check403 = TRUE;
CheckRedirect = TRUE;

port = get_http_port( default:80 );

host = http_host_name( dont_add_port:TRUE );
if( debug ) display( ":: Checking directories on Hostname/IP:port " + host + ":" + port + "...\n" );

if( http_get_is_marked_broken( port:port, host:host ) )
  exit( 0 );

#counter for current failed requests
failedReqs = 0;
#counter for max failed requests
#The NVT will exit if this is reached
#TBD: Make this configurable?
maxFailedReqs = 3;

# pull the robots.txt file
if( debug ) display( ":: Checking for robots.txt...\n" );
req = http_get( item:"/robots.txt", port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( isnull( res ) ) failedReqs++;

if( res =~ "^HTTP/1\.[01] 200" ) {

  strings = split( res );

  foreach string( strings ) {

    if( egrep( pattern:"(dis)?allow:.*/", string:string, icase:TRUE ) &&
        ! egrep( pattern:"(dis)?allow:.*\.", string:string, icase:TRUE ) ) {

      # yes, i suck at regex's in nasl. I want my \s+!
      robot_dir = ereg_replace( pattern:"(dis)?allow:\W*/(.*)$", string:string, replace:"\2", icase:TRUE );
      robot_dir = ereg_replace( pattern:"\W*$", string:robot_dir, replace:"", icase:TRUE );
      robot_dir = ereg_replace( pattern:"/$|\?$", string:robot_dir, replace:"", icase:TRUE );

      if( robot_dir != '' ) {
        testDirList = make_list( testDirList, robot_dir );
        if( debug ) display(":: Directory '", robot_dir, "' added to test list\n");
      }
    }
  }
}

# pull the CVS/Entries file
if( debug ) display( ":: Checking for /CVS/Entries...\n" );
req = http_get( item:"/CVS/Entries", port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( isnull( res ) ) failedReqs++;

if( res =~ "^HTTP/1\.[01] 200" ) {

  strings = split( res, string( "\n" ) );

  foreach string( strings ) {

    if( ereg( pattern:"^D/(.*)////", string:string, icase:TRUE ) ) {

      cvs_dir = ereg_replace( pattern:"D/(.*)////.*", string:string, replace:"\1", icase:TRUE );

      if( cvs_dir != '' ) {
        testDirList = make_list( testDirList, cvs_dir );
        if( debug ) display( ":: Directory '", cvs_dir, "' added to test list\n" );
      }
    }
  }
}

# test for servers which return 200/403/401 for everything
req = http_get( item:"/non-existent" + rand() + "/", port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( isnull( res ) ) failedReqs++;

if( res =~ "^HTTP/1\.[01] 200" ) {

  fake404 = 0;

  if( debug ) display( ":: This server returns 200 for non-existent directories.\n" );

  foreach errmsg( errmessages_404 ) {
    if( egrep( pattern:errmsg, string:res, icase:TRUE ) && ! fake404 ) {
      fake404 = errmsg;
      if( debug ) display( ":: Using '", fake404, "' as an indication of a 404 error\n" );
      break;
    }
  }

  if( ! fake404 ) {
    if( debug ) display( ":: Could not find an error string to match against for the fake 404 response.\n" );
    if( debug ) display( ":: Checks which rely on 200 responses are being disabled\n" );
    Check200 = FALSE;
  }
} else {
  fake404 = string( "BadString0987654321*DDI*" );
}

if( res =~ "^HTTP/1\.[01] 401" ) {
  if( debug ) display( ":: This server requires authentication for non-existent directories, disabling 401 checks.\n" );
  Check401 = FALSE;
}

if( res =~ "^HTTP/1\.[01] 403" ) {
  if( debug ) display( ":: This server returns a 403 for non-existent directories, disabling 403 checks.\n" );
  Check403 = FALSE;
}

if( res =~ "^HTTP/1\.[01] 30[0-8]" ) {
  if( debug ) display( ":: This server returns a redirect for non-existent directories, disabling redirect checks.\n" );
  CheckRedirect = FALSE;
}

# start the actual directory scan
ScanRootDir = "/";

start = unixtime();
if( debug ) display( ":: Starting the directory scan...\n" );

# We make the list unique at the end to avoid having doubled
# entries from e.g. the robots.txt and for easier maintenance
# of the initial list which could contain multiple entries.
testDirList = make_list_unique( testDirList );

foreach cdir( testDirList ) {

  url = ScanRootDir + cdir;
  res = http_get_cache( item:url + "/", port:port );

  if( isnull( res ) ) {
    failedReqs++;
    if( failedReqs >= maxFailedReqs ) {
      if( debug ) display( ":: Max number of failed requests (" + maxFailedReqs + ") reached, exiting...\n" );
      exit( 0 );
    }
    continue;
  }

  if( cgi_dirs_exclude_servermanual ) {

    # Ignore Apache2 manual if it exists. This is just huge static content
    # and slows down the scanning without any real benefit.
    if( url =~ "^/manual" ) {
      res = http_get_cache( item:"/manual/en/index.html", port:port );
      if( "Documentation - Apache HTTP Server" >< res ) {
        set_kb_item( name:"www/" + host + "/" + port + "/content/servermanual_directories", value:report_vuln_url( port:port, url:url, url_only:TRUE ) + ", Content: Apache HTTP Server Manual" );
        continue;
      }
    }

    # Similar to the above for Tomcat
    if( url =~ "^/tomcat-docs" ) {
      res = http_get_cache( item:"/tomcat-docs/", port:port );
      if( "Apache Tomcat" >< res && "Documentation Index" >< res ) {
        set_kb_item( name:"www/" + host + "/" + port + "/content/servermanual_directories", value:report_vuln_url( port:port, url:url, url_only:TRUE ) + ", Content: Apache Tomcat Documentation" );
        continue;
      }
    }
  }

  http_code = int( substr( res, 9, 11 ) );
  if( ! res ) res = "BogusBogusBogus";

  if( Check200 && http_code == 200 && ! ( egrep( pattern:fake404, string:res, icase:TRUE ) ) ) {

    if( debug ) display( ":: Discovered: " , ScanRootDir, cdir, "\n" );

    add_discovered_list( dir:ScanRootDir + cdir, port:port, host:host );
  }

  # Pass any redirects we're getting to webmirror.nasl for further processing
  if( CheckRedirect && http_code =~ "^30[0-8]$" ) {

    if( debug ) {
      display( ":: Got a '", http_code, "' redirect for ", ScanRootDir, cdir, ", trying to extract the location...\n" );
      redirect = http_extract_location_from_redirect( port:port, data:res, debug:TRUE );
    } else {
      redirect = http_extract_location_from_redirect( port:port, data:res, debug:FALSE );
    }

    if( redirect ) {
      if( debug ) display( ":: Passing extracted redirect ", redirect ," to webmirror.nasl...\n" );
      set_kb_item( name:"DDI_Directory_Scanner/" + port + "/received_redirects", value:redirect );
      set_kb_item( name:"DDI_Directory_Scanner/" + host + "/" + port + "/received_redirects", value:redirect );
    }
  }

  if( Check403 && http_code == 403 ) {

    if( debug ) display( ":: Got a 403 for ", ScanRootDir, cdir, ", checking for file in the directory...\n" );

    req = http_get( item:ScanRootDir + cdir + "/NonExistent.html", port:port );
    res = http_keepalive_send_recv( data:req, port:port, bodyonly:FALSE );

    if( res =~ "^HTTP/1\.[01] 403" ) {
      # the whole directory appears to be protected
      if( debug ) display( "::   403 applies to the entire directory \n" );
    } else {
      if( debug ) display( "::   403 applies to just directory indexes \n" );

      # the directory just has indexes turned off
      if( debug ) display( ":: Discovered: " , ScanRootDir, cdir, "\n" );
      add_discovered_list( dir:ScanRootDir + cdir, port:port, host:host );
    }
  }

  if( Check401 && http_code == 401 ) {

    if( header = egrep( pattern:"^WWW-Authenticate:", string:res, icase:TRUE ) ) {
      if( debug ) display( ":: Got a 401 for ", ScanRootDir + cdir, " containing a WWW-Authenticate header, adding to the dirs requiring auth...\n" );
      basic_auth = http_extract_basic_auth( data:res );
      add_auth_dir_list( dir:ScanRootDir + cdir, port:port, host:host, basic:basic_auth["basic_auth"], realm:basic_auth["realm"] );
    } else {
      if( debug ) display( ":: Got a 401 for ", ScanRootDir + cdir, " WITHOUT a WWW-Authenticate header, NOT adding to the dirs requiring auth...\n" );
    }
  }
  #TBD: Make this configurable?
  if( unixtime() - start > 80 ) exit( 0 );
}

exit( 0 );
