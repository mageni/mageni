###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_soliddb_41653.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# IBM SolidDB 'solid.exe' Handshake Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.100722");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-21 19:56:46 +0200 (Wed, 21 Jul 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2771");
  script_bugtraq_id(41653);

  script_name("IBM SolidDB 'solid.exe' Handshake Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/41653");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21439148");
  script_xref(name:"URL", value:"http://www.solidtech.com/en/products/relationaldatabasemanagementsoftware/embed.asp");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-125/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_soliddb_detect.nasl");
  script_require_ports("Services/soliddb", 1315);
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"The vendor released updates to address this issue. Please see the
references for more information.");
  script_tag(name:"summary", value:"IBM SolidDB is prone to a remote code-execution vulnerability.

An attacker can exploit this issue to execute arbitrary code with
SYSTEM user privileges. Failed exploit attempts will result in a denial-of-
service condition.

The vulnerability is reported in version 6.5 FP1 (6.5.0.1). Prior
versions may also be affected.");
  exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/soliddb");
if(!port)port=1315;

if(!get_port_state(port))exit(0);

if(!v = get_kb_item(string("soliddb/",port,"/version")))exit(0);

if("Build" >< v) {
  version = eregmatch(pattern:"^[^ ]+", string:v);
  version = version[0];
} else {
  version = v;
}

if(version_is_equal(version:version, test_version:"6.5.0.1")) {
  security_message(port:port);
  exit(0);
}
