# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803979");
  script_version("2023-04-05T10:10:37+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-05 10:10:37 +0000 (Wed, 05 Apr 2023)");
  script_tag(name:"creation_date", value:"2013-12-16 18:17:29 +0530 (Mon, 16 Dec 2013)");
  script_name("TYPO3 Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://typo3.org/");

  script_tag(name:"summary", value:"HTTP based detection of TYPO3.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

rootInstalled = FALSE;

# <meta name="generator" content="TYPO3 CMS" />
# <meta name="generator" content="TYPO3 7.0 CMS">
# <meta name="generator" content="TYPO3 4.5, http://typo3.org/, &#169; Kasper Sk&#229;rh&#248;j 1998-2015, extensions are copyright of their respective owners." />
# <meta name="generator" content="TYPO3 CMS, https://typo3.org/, &amp;#169; Kasper Sk&amp;#229;rh&amp;#248;j 1998-2023, extensions are copyright of their respective owners." />
# <meta name="author" content="TYPO3 10 Demo" />
generator_pattern = '<meta name="generator" content="TYPO3';
pattern = 'content="TYPO3 ([0-9a-z.]+)';

foreach dir( make_list_unique( "/", "/cms", "/typo", "/typo3", http_cgi_dirs( port:port ) ) ) {

  if( rootInstalled )
    break;

  concl = "";
  installed = FALSE;
  version = "unknown";
  install = dir;
  if( dir == "/" )
    dir = "";

  url1 = dir + "/";
  res1 = http_get_cache( item:url1, port:port );

  url2 = dir + "/typo3/index.php";
  res2 = http_get_cache( item:url2, port:port );

  url3 = dir + "/typo3_src/ChangeLog";
  res3 = http_get_cache( item:url3, port:port );

  if( ! res3 || "TYPO3 Release Team" >!< res3 ) {
    url3 = dir + "/ChangeLog";
    res3 = http_get_cache( item:url3 , port:port );
  }

  if( res3 && res3 =~ "^HTTP/1\.[01] 200" && "TYPO3 Release Team" >< res3 ) {
    # Release of TYPO3 4.5.40
    # Release of TYPO3 7.6.41
    ver3 = eregmatch( pattern:"Release of TYPO3 ([0-9a-z.]+)", string:res3 );
    installed = TRUE;
    conclUrl = http_report_vuln_url( port:port, url:url3, url_only:TRUE );
  }

  if( res1 && res1 =~ "^HTTP/1\.[01] 200" && ( generator_pattern >< res1 || ( "typo3conf/" >< res1 && "typo3temp/" >< res1 ) ) ) {
    ver1 = eregmatch( pattern:pattern, string:res1 );
    installed = TRUE;
    if( conclUrl )
      conclUrl += '\n';
    conclUrl += http_report_vuln_url( port:port, url:url1, url_only:TRUE );

    if( _concl = egrep( string:res1, pattern:generator_pattern, icase:FALSE ) )
      concl = chomp( _concl );
  }

  if( res2 && res2 =~ "^HTTP/1\.[01] 200" && ( generator_pattern >< res2 || "typo3temp" >< res2 ) ) {
    ver2 = eregmatch( pattern:pattern, string:res2 );
    installed = TRUE;
    if( conclUrl )
      conclUrl += '\n';
    conclUrl += http_report_vuln_url( port:port, url:url2, url_only:TRUE );

    if( _concl = egrep( string:res2, pattern:generator_pattern, icase:FALSE ) )
      concl = chomp( _concl );
  }

  if( ! isnull( ver3[1] ) ) {
    if( concl )
      concl += '\n';
    concl += ver3[0];
    version = ver3[1];
  } else if( ! isnull( ver1[1] ) ) {
    if( concl )
      concl += '\n';
    concl += ver1[0];
    version = ver1[1];
  } else if( ! isnull( ver2[1] ) ) {
    if( concl )
      concl += '\n';
    concl += ver2[0];
    version = ver2[1];
  }

  # We only want ro run this if:
  # - TYPO3 wasn't detected at all
  # - the version is unknown
  # - only the major version like 10 was extracted
  # The last two points are covered by the regex
  if( ! installed || ( installed && version !~ "[0-9]+\.[0-9]+" ) ) {

    foreach url4( make_list( dir + "/typo3/sysext/recordlist/composer.json", dir + "/typo3/sysext/sys_note/composer.json",
                             dir + "/typo3/sysext/t3editor/composer.json", dir + "/typo3/sysext/opendocs/composer.json" ) ) {

      res4 = http_get_cache( item:url4, port:port );
      if( res4 && res4 =~ "^HTTP/1\.[01] 200" && "TYPO3 Core Team" >< res4 ) {
        if( conclUrl )
          conclUrl += '\n';
        conclUrl += http_report_vuln_url( port:port, url:url4, url_only:TRUE );
        installed = TRUE;

        # "require": {
        #   "php": "^7.0",
        #   "typo3/cms-core": "8.7.44"
        # },
        ver4 = eregmatch( pattern:'typo3/cms-core"\\s*:\\s*"([0-9a-z.]+)"', string:res4 );
        if( ver4[1] ) {
          concl = ver4[0];
          version = ver4[1];
          break;
        }
      }
    }
  }

  if( installed ) {

    if( dir == "" )
      rootInstalled = TRUE;

    set_kb_item( name:"typo3/detected", value:TRUE );
    set_kb_item( name:"typo3/http/detected", value:TRUE );
    register_and_report_cpe( app:"TYPO3", ver:version, concluded:concl, base:"cpe:/a:typo3:typo3:", expr:"([0-9a-z.]+)", insloc:install, regPort:port, conclUrl:conclUrl, regService:"www" );
  }
}

exit( 0 );
