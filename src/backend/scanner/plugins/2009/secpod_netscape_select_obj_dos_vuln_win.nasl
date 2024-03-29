###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_netscape_select_obj_dos_vuln_win.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Netscape 'selecti()' Object Denial Of Service Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900393");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2542", "CVE-2009-1692");
  script_bugtraq_id(35446);
  script_name("Netscape 'select()' Object Denial Of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9160");
  script_xref(name:"URL", value:"http://www.g-sec.lu/one-bug-to-rule-them-all.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_netscape_detect_win.nasl");
  script_mandatory_keys("Netscape/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of
service.");
  script_tag(name:"affected", value:"Netscape version 6 and 8 on Windows");
  script_tag(name:"insight", value:"Error occurs while calling the 'select()' method with a large
integer that results in continuous allocation of x+n bytes of memory exhausting
memory after a while.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Netscape browser and is prone to
Denial of Service vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


netscapeVer = get_kb_item("Netscape/Win/Ver");
if(netscapeVer =~ "^(6|8)\..*"){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
