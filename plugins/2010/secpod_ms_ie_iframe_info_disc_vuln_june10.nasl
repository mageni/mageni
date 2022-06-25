###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_iframe_info_disc_vuln_june10.nasl 11553 2018-09-22 14:22:01Z cfischer $
#
# Microsoft IE cross-domain IFRAME gadgets keystrokes steal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902210");
  script_version("$Revision: 11553 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 16:22:01 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-07-01 15:58:11 +0200 (Thu, 01 Jul 2010)");
  script_cve_id("CVE-2010-2442");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Microsoft IE cross-domain IFRAME gadgets keystrokes steal Vulnerability");
  script_xref(name:"URL", value:"http://vul.hackerjournals.com/?p=10196");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=552255");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow cross-domain iframe gadgets
to steal keystrokes (including password field entries) transparently.");
  script_tag(name:"affected", value:"Microsoft Internet Explorer version 8.0.7600.16385 and prior.");
  script_tag(name:"insight", value:"The flaw is due to improper handling of 'top.focus()' function,
which does not properly restrict focus changes, which allows remote attackers to
read keystrokes via 'cross-domain IFRAME gadgets'");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Internet Explorer and is prone to
cross-domain iframe gadgets keystrokes steal vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_in_range(version:ieVer, test_version:"8.0", test_version2:"8.0.7600.16385")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
