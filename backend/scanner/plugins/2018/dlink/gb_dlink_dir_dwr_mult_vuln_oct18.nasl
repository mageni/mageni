###############################################################################
# OpenVAS Vulnerability Test
#
# D-Link DIR/DWR Devices Multiple Vulnerabilities - Oct18
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE_PREFIX = "cpe:/o:dlink";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108487");
  script_version("2019-05-09T15:03:03+0000");
  script_cve_id("CVE-2018-10822", "CVE-2018-10823", "CVE-2018-10824");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-09 15:03:03 +0000 (Thu, 09 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-26 13:53:11 +0100 (Mon, 26 Nov 2018)");

  script_name("D-Link DIR/DWR Devices Multiple Vulnerabilities - Oct18");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dsl_detect.nasl", "gb_dlink_dap_detect.nasl", "gb_dlink_dir_detect.nasl", "gb_dlink_dwr_detect.nasl");
  script_mandatory_keys("Host/is_dlink_device"); # nb: Experiences in the past have shown that various different devices might be affected
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10093");
  script_xref(name:"URL", value:"http://sploit.tech/2018/10/12/D-Link.html");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2018/Oct/36");

  script_tag(name:"summary", value:"The host is a D-Link (DIR/DWR) device which is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request
  and check whether it is possible to read a file on the filesystem.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - a directory traversal vulnerability in the web interface (CVE-2018-10822) caused by an incorrect
  fix for CVE-2017-6190.

  - the administrative password stored in plaintext in the /tmp/XXX/0 file (CVE-2018-10824).

  - the possibility to injection code shell commands as an authenticated user into the Sip parameter
  of the chkisg.htm page (CVE-2018-10823).");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read arbitrary files on the target system, extract plain text
  passwords or execute remote commands.");

  script_tag(name:"affected", value:"DWR-116 through 1.06,

  DIR-140L and DIR-640L through 1.02,

  DWR-512, DWR-712, DWR-912 and DWR-921 through 2.02,

  DWR-111 through 1.01.

  Other devices, models or versions might be also affected.");

  script_tag(name:"solution", value:"See the vendor advisory for a solution.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www", first_cpe_only:TRUE ) )
  exit( 0 );

port = infos["port"];
CPE  = infos["cpe"];

files = traversal_files( "linux" );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

foreach pattern( keys( files ) ) {

  file = files[pattern];
  url  = dir + "/uir//" + file;

  if( http_vuln_check( port:port, url:url, pattern:pattern, check_header:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
