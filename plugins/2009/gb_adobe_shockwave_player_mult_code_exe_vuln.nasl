###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Shockwave Player Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800971");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-11-09 14:01:44 +0100 (Mon, 09 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3463", "CVE-2009-3464", "CVE-2009-3465",
                "CVE-2009-3466");
  script_bugtraq_id(36905);
  script_name("Adobe Shockwave Player Multiple Remote Code Execution Vulnerabilities");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3134");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Nov/1023123.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-16.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code in the
  context of the affected application by tricking a user into visiting a
  specially crafted web page.");
  script_tag(name:"affected", value:"Adobe Shockwave Player prior to 11.5.2.602 on Windows.");
  script_tag(name:"insight", value:"- Multiple errors occur due to the use of invalid index and invalid pointer
    while processing specially crafted Shockwave content.

  - An error while processing invalid string lengths can result in memory
    corruption.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player 11.5.2.602.");
  script_tag(name:"summary", value:"This host is installed with Adobe Shockwave Player and is prone
  to Multiple Remote Code Execution Vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer)
  exit(0);

if(version_is_less(version:shockVer, test_version:"11.5.2.602")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
