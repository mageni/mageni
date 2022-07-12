###############################################################################
# OpenVAS Vulnerability Test
#
# RealNetworks Helix Server Multiple Remote Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103475");
  script_bugtraq_id(52929);
  script_cve_id("CVE-2012-0942", "CVE-2012-1923", "CVE-2012-1984", "CVE-2012-1985", "CVE-2012-2267", "CVE-2012-2268");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2019-05-24T11:20:30+0000");

  script_name("RealNetworks Helix Server Multiple Remote Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52929");
  script_xref(name:"URL", value:"http://www.realnetworks.com/products-services/helix-server-proxy.aspx");
  script_xref(name:"URL", value:"http://helixproducts.real.com/docs/security/SecurityUpdate04022012HS.pdf");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2012-9/");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2012-8/");

  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2012-04-23 14:15:20 +0200 (Mon, 23 Apr 2012)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("rtsp_detect.nasl");
  script_require_ports("Services/rtsp", 554);

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"RealNetworks Helix Server is prone to multiple remote vulnerabilities.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to execute arbitrary code within
the context of the affected application, cause denial-of service
conditions, retrieve potentially sensitive information, execute
arbitrary script code in the browser of an unsuspecting user in the
context of the affected site, and steal cookie-based authentication
credentials.");

  script_tag(name:"affected", value:"RealNetworks Helix Server 14.2.0.212 is vulnerable, other versions may
also be affected.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/rtsp");
if(!port)port = 554;
if(!get_port_state(port))exit(0);

if(!server = get_kb_item(string("RTSP/",port,"/Server")))exit(0);
if("Server: Helix" >!< server)exit(0);

version = eregmatch(pattern:"Version ([0-9.]+)", string: server);

if(isnull(version[1]))exit(0);

if(version_in_range(version:version[1], test_version:"14", test_version2:"14.2")) {

    security_message(port:port);
    exit(0);

} else {

  exit(99);

}

exit(0);
