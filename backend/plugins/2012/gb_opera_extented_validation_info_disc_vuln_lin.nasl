###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_extented_validation_info_disc_vuln_lin.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Opera Extended Validation Information Disclosure Vulnerabilities (Linux)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802830");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2011-3388", "CVE-2011-3389");
  script_bugtraq_id(49388);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-06 12:13:30 +0530 (Fri, 06 Apr 2012)");
  script_name("Opera Extended Validation Information Disclosure Vulnerabilities (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45791");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1025997");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1000/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to steal sensitive security
  information.");
  script_tag(name:"affected", value:"Opera version before 11.51 on Linux");
  script_tag(name:"insight", value:"Multiple flaws are due to an error when loading content from trusted
  sources in an unspecified sequence that causes the address field and page
  information dialog to contain security information based on the trusted site
  and loading an insecure site to appear secure via unspecified actions related
  to Extended Validation.");
  script_tag(name:"solution", value:"Upgrade to Opera version 11.51 or later.");
  script_tag(name:"summary", value:"The host is installed with Opera and is prone to information
  disclosure vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.opera.com/download/");
  exit(0);
}


include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"11.51")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
