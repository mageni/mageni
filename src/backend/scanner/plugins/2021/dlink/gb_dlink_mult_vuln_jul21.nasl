# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE_PREFIX = "cpe:/o:d-link";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117609");
  script_version("2021-08-03T09:26:24+0000");
  script_tag(name:"last_modification", value:"2021-08-04 10:51:24 +0000 (Wed, 04 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-03 08:36:41 +0000 (Tue, 03 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-21816", "CVE-2021-21817", "CVE-2021-21818", "CVE-2021-21819", "CVE-2021-21820");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DIR-3040 < 1.13B03 Hotfix Multiple Vulnerabilities - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dns_detect.nasl", "gb_dlink_dsl_detect.nasl", "gb_dlink_dap_detect.nasl", "gb_dlink_dir_detect.nasl", "gb_dlink_dwr_detect.nasl");
  script_mandatory_keys("Host/is_dlink_device"); # nb: Experiences in the past have shown that various different devices might be affected
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"D-Link DIR-3040 devices are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-21816: Syslog information disclosure vulnerability

  - CVE-2021-21817: Zebra IP Routing Manager information disclosure vulnerability

  - CVE-2021-21818: Zebra IP Routing Manager hard-coded password vulnerability

  - CVE-2021-21819: Libcli command injection vulnerability

  - CVE-2021-21820: Libcli Test Environment hard-coded password vulnerability");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"D-Link DIR-3040 devices. Other D-Link products might be affected as well.");

  script_tag(name:"solution", value:"Update to 1.13B03 Hotfix or later.");

  script_xref(name:"URL", value:"https://support.dlink.com/resource/SECURITY_ADVISEMENTS/DIR-3040/REVA/DIR-3040_REVA_RELEASE_NOTES_v1.13B03_HOTFIX.pdf");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2021-1281");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2021-1282");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2021-1283");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2021-1284");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2021-1285");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

port = infos["port"];
cpe = infos["cpe"];

if( ! dir = get_app_location( cpe:cpe, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/messages";

buf = http_get_cache( item:url, port:port );
if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

# e.g.:
# 2021-04-05 11:36:07 syslog: dnssd_clientstub ConnectToServer: connect()-> No of tries: 1
# 2021-04-05 11:36:16 syslog: dnssd_clientstub ConnectToServer: connect() failed path:/var/run/mdnsd Socket:27 Err:-1 Errno:0 Success
if( egrep( pattern:"^[0-9]+-[0-9]+-[0-9]+ [0-9]+:[0-9]+:[0-9]+ syslog: ", string:buf ) ) {
  report = "It was possible to read the syslog file at " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  body = http_extract_body_from_response( data:buf );
  if( body )
    report += '\n\nContent (truncated):\n' + substr( body, 0, 500 );
  security_message( port:port, data:chomp( report ) );
  exit( 0 );
}

exit( 99 );