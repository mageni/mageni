###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_blackberry_desktop_software_sec_bypass_vuln.nasl 11553 2018-09-22 14:22:01Z cfischer $
#
# BlackBerry Desktop Software Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By:
# Antu Sanadi <santu@secpod.com> on 2010-10-12
# Updated the version check
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801523");
  script_version("$Revision: 11553 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 16:22:01 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-10-08 08:29:14 +0200 (Fri, 08 Oct 2010)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_cve_id("CVE-2010-3741");
  script_name("BlackBerry Desktop Software Security Bypass Vulnerability");
  script_xref(name:"URL", value:"http://it.slashdot.org/story/10/10/01/166226/");
  script_xref(name:"URL", value:"http://twitter.com/elcomsoft/statuses/25954970586");
  script_xref(name:"URL", value:"http://blog.crackpassword.com/2010/09/smartphone-forensics-cracking-blackberry-backup-passwords/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Brute force attacks");
  script_dependencies("secpod_blackberry_desktop_software_detect_win.nasl");
  script_mandatory_keys("BlackBerry/Desktop/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to steal or guess
document's password via a brute force attacks.");
  script_tag(name:"affected", value:"BlackBerry Desktop Software version 6.0.0.43 and prior.");
  script_tag(name:"insight", value:"The flaw is cused due to error in 'offline backup' mechanism in
'Research In Motion' (RIM), which uses single-iteration 'PBKDF2', which
makes it easier for local users to decrypt a '.ipd' file via a brute-force
attack.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host has BlackBerry Desktop Software installed and is prone to
security bypass vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

bbdVer = get_kb_item("BlackBerry/Desktop/Win/Ver");
if(!bbdVer){
  exit(0);
}

if(version_is_less_equal(version:bbdVer, test_version:"6.0.0.43")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
