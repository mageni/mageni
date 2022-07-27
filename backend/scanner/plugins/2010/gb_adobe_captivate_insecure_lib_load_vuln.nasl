###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_captivate_insecure_lib_load_vuln.nasl 11498 2018-09-20 10:34:34Z jschulte $
#
# Adobe Captivate Insecure Library Loading Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801267");
  script_version("$Revision: 11498 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-20 12:34:34 +0200 (Thu, 20 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-09-03 15:47:26 +0200 (Fri, 03 Sep 2010)");
  script_cve_id("CVE-2010-3191");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Captivate Insecure Library Loading Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41233");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_captivate_detect.nasl");
  script_mandatory_keys("Adobe/Captivate/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
arbitrary code and conduct DLL hijacking attacks.");
  script_tag(name:"affected", value:"Adobe Captivate Version 5.0.0.596");
  script_tag(name:"insight", value:"This flaw is due to the application insecurely loading certain
libraries from the current working directory, which could allow attackers
to execute arbitrary code by tricking a user into opening a file from a
network share.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Adobe Captivate and is prone to
Insecure Library Loading vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");

capVer = get_kb_item("Adobe/Captivate/Ver");

if(capVer != NULL)
{
  if( version_in_range(version:capVer, test_version: "5.0.0.000", test_version2: "5.0.0.596") ){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
