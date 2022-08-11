###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_arg_inj_vuln.nasl 12623 2018-12-03 13:11:38Z cfischer $
#
# Microsoft Internet Explorer Argument Injection Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900187");
  script_version("$Revision: 12623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 14:11:38 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-12-31 15:44:52 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5750");
  script_name("Microsoft Internet Explorer Argument Injection Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7566");
  script_xref(name:"URL", value:"http://retrogod.altervista.org/9sg_chrome.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary codes with
  the user privileges and cause argument injection in the context of the
  vulnerable application.");
  script_tag(name:"affected", value:"Microsoft, Internet Explorer version 8 beta 2 and prior on Windows.");
  script_tag(name:"insight", value:"The flaw is due to lack of sanitization check of user supplied input which
  causes remote command execution in the context of the application via

  - -renderer-path option in a chromehtml: URI.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host has installed Internet Explorer and is prone to Argument
  Injection vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.microsoft.com/windows/downloads/ie/getitnow.mspx");
  exit(0);
}


include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_in_range(version:ieVer, test_version:"8.0",
                    test_version2:"8.0.6001.18241")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
