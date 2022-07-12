###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2016-0010_esxi6_remote_active.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# VMSA-2016-0010 (CVE-2016-5331) ESXi: VMware product updates address multiple important security issues (remote active check)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105853");
  script_cve_id("CVE-2016-5331");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 13994 $");

  script_name("VMSA-2016-0010 (CVE-2016-5331) ESXi: VMware product updates address multiple important security issues (remote active check)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0010.html");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"ESXi contain an HTTP header injection vulnerability due to lack of input validation. An attacker can exploit
  this issue to set arbitrary HTTP response headers and cookies, which may allow for cross-site scripting and malicious redirect attacks.");

  script_tag(name:"affected", value:"ESXi 6.0 without patch ESXi600-201603101-SG");

  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-08-08 13:06:24 +0200 (Mon, 08 Aug 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/port");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_kb_item( "VMware/ESX/port" ) )
  exit( 0 );

vtstrings = get_vt_strings();
vtstring = vtstrings["default"];
vtstring_lo = vtstrings["lowercase"];

co = 'Set-Cookie:%20' + vtstring + '=' + rand();
co_s = str_replace( string:co, find:'%20', replace:' ');

h1 = vtstring_lo + ':%20' + rand();
h1_s = str_replace( string:h1, find:'%20', replace:' ');

url = '/?syss%0d%0a' + co + '%0d%0a' + h1;

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "^HTTP/1\.[01] 303" )
{
  if( egrep( pattern:'^' + co_s, string:buf ) && egrep( pattern:'^' + h1_s, string:buf ) )
  {
    report = report_vuln_url(  port:port, url:url );
    report += '\n\nResponse:\n\n' + buf;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );