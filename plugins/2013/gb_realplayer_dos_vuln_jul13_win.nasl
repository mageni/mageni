###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_dos_vuln_jul13_win.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# RealNetworks RealPlayer Denial of Service Vulnerability - July13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803910");
  script_version("$Revision: 11401 $");
  script_cve_id("CVE-2013-3299");
  script_bugtraq_id(60903);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-07-17 16:46:46 +0530 (Wed, 17 Jul 2013)");
  script_name("RealNetworks RealPlayer Denial of Service Vulnerability - July13 (Windows)");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to cause denial of service
condition via crafted HTML file.");
  script_tag(name:"affected", value:"RealPlayer versions 16.0.2.32 and prior on Windows.");
  script_tag(name:"insight", value:"Flaw within the unknown function of the component HTML Handler.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"summary", value:"This host is installed with RealPlayer which is prone to Denial of
Service vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://securitytracker.com/id/1028732");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Jul/18");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  exit(0);
}


include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(!rpVer){
  exit(0);
}

if(version_is_less_equal(version:rpVer, test_version:"16.0.2.32"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
