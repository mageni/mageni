###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rn_helix_39490.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# RealNetworks Helix and Helix Mobile Server Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100579");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-15 19:15:10 +0200 (Thu, 15 Apr 2010)");
  script_bugtraq_id(39490);
  script_cve_id("CVE-2010-1317", "CVE-2010-1318", "CVE-2010-1319");

  script_name("RealNetworks Helix and Helix Mobile Server Multiple Remote Code Execution Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39490");
  script_xref(name:"URL", value:"http://www.realnetworks.com/products/media_delivery.html");
  script_xref(name:"URL", value:"http://www.realnetworks.com/uploadedFiles/Support/helix-support/SecurityUpdate041410HS.pdf");

  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("rtsp_detect.nasl");
  script_require_ports("Services/rtsp", 554);
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"The vendor released Helix Server and Helix Mobile Server 14.0 to
  address these issues. Please see the references for more information.");
  script_tag(name:"summary", value:"RealNetworks Helix Server and Helix Mobile Server are prone to
  multiple memory-corruption vulnerabilities that can allow attackers to
  execute remote code.

  Exploiting these issues may allow attackers to gain unauthorized
  access to affected computers. Failed attempts may cause crashes and
  deny service to legitimate users of the application.

  These issues affect versions prior to Helix Server and Helix Mobile
  Server 14.0.");
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

if(version_is_less(version:version[1], test_version:"14")) {
  security_message(port:port);
  exit(0);
}

exit(0);

