###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_js_impl_info_disc_vuln_win.nasl 11552 2018-09-22 13:45:08Z cfischer $
#
# Apple Safari JavaScript Implementation Information Disclosure Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802284");
  script_version("$Revision: 11552 $");
  script_cve_id("CVE-2010-5070");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 15:45:08 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-12-09 12:12:12 +0530 (Fri, 09 Dec 2011)");
  script_name("Apple Safari JavaScript Implementation Information Disclosure Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://w2spconf.com/2010/papers/p26.pdf");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain access to
sensitive information and launch other attacks.");
  script_tag(name:"affected", value:"Apple Safari version 4");
  script_tag(name:"insight", value:"The flaw is due to the JavaScript implementation is not properly
restrict the set of values contained in the object returned by the
getComputedStyle method, which allows remote attackers to obtain sensitive
information about visited web pages.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is installed with Apple Safari web browser and is prone
to information disclosure vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

if(version_in_range(version:safVer,test_version:"5.26.12.2",test_version2:"5.31.22.7")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
