# SPDX-FileCopyrightText: 2003 Randy Matz
# SPDX-FileCopyrightText: New / rewritten code and metadata since 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11229");
  script_version("2023-12-14T08:20:35+0000");
  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  # avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2008-0149",
                "CVE-2023-49282",
                "CVE-2023-49283");
  script_tag(name:"last_modification", value:"2023-12-14 08:20:35 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 13:24:00 +0000 (Tue, 12 Dec 2023)");
  script_name("phpinfo() Output Reporting (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Randy Matz");
  script_family("Web application abuses");
  script_dependencies("gb_phpinfo_output_detect.nasl");
  script_mandatory_keys("php/phpinfo/detected");

  script_xref(name:"URL", value:"https://www.php.net/manual/en/function.phpinfo.php");

  script_tag(name:"summary", value:"Reporting of files containing the output of the phpinfo() PHP
  function previously detected via HTTP.");

  script_tag(name:"vuldetect", value:"This script reports files identified by the following separate
  VT: 'phpinfo() Output Detection (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.108474).");

  script_tag(name:"insight", value:"Many PHP installation tutorials instruct the user to create a
  file called phpinfo.php or similar containing the phpinfo() statement. Such a file is often left
  back in the webserver directory.");

  script_tag(name:"impact", value:"Some of the information that can be gathered from this file includes:

  The username of the user running the PHP process, if it is a sudo user, the IP address of the host, the web server
  version, the system version (Unix, Linux, Windows, ...), and the root directory of the web server.");

  script_tag(name:"affected", value:"All systems exposing a file containing the output of the
  phpinfo() PHP function.

  This VT is also reporting if an affected endpoint for the following products have been identified:

  - CVE-2008-0149: TUTOS

  - CVE-2023-49282, CVE-2023-49283: Microsoft Graph PHP SDK");

  script_tag(name:"solution", value:"Delete the listed files or restrict access to them.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

report = 'The following files are calling the function phpinfo() which disclose potentially sensitive information:\n';

port = http_get_port( default:80 );
# nb: Don't use http_can_host_php() here as this VT is reporting PHP as well
# and http_can_host_php() could fail if no PHP was detected before...

host = http_host_name( dont_add_port:TRUE );

if( ! get_kb_item( "php/phpinfo/" + host + "/" + port + "/detected" ) )
  exit( 99 );

url_list = get_kb_list( "www/" + host + "/" + port + "/content/phpinfo_script/reporting" );
if( ! is_array( url_list ) )
  exit( 99 );

# nb: Sort to not report differences on delta reports just the order is different.
url_list = sort( url_list );

foreach url( url_list ) {
  report += '\n' + url;
}

security_message( port:port, data:report );
exit( 0 );
