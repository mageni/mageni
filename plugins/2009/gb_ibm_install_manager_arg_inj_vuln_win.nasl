###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_install_manager_arg_inj_vuln_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# IBM Installation Manager URI Handling Argument Injection Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801011");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-10-12 07:28:01 +0200 (Mon, 12 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3518");
  script_bugtraq_id(36549);
  script_name("IBM Installation Manager URI Handling Argument Injection Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36906");
  script_xref(name:"URL", value:"http://retrogod.altervista.org/9sg_ibm_uri.html");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2792");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ibm_install_manager_detect_win.nasl");
  script_mandatory_keys("IBM/InstallMang/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  code or compromise a user's system.");

  script_tag(name:"affected", value:"IBM Installation Manager 1.3.2 and prior on Windows.");

  script_tag(name:"insight", value:"The flaw is due to error in 'IBMIM.exe' when handling arguments
  received via an 'iim:' URI. This can be exploited to load an arbitrary library
  from a network share via a specially crafted '-vm' argument.");

  script_tag(name:"solution", value:"Upgrade to version 1.3.3 or later.");

  script_tag(name:"summary", value:"This host has IBM Installation Manager installed and is prone to
  Argument Injection vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

iimVer = get_kb_item("IBM/InstallMang/Win/Ver");

if(iimVer != NULL)
{
  if(version_is_less_equal(version:iimVer, test_version:"1.3.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
