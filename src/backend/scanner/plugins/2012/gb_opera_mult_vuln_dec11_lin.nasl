###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln_dec11_lin.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Opera Multiple Vulnerabilities - December11 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802834");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2011-4681", "CVE-2011-4682", "CVE-2011-4683", "CVE-2011-4684",
                "CVE-2011-4685", "CVE-2011-4686", "CVE-2011-4687");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-09 16:54:45 +0530 (Mon, 09 Apr 2012)");
  script_name("Opera Multiple Vulnerabilities - December11 (Linux)");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1003/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1005/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unix/1160/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions, or cause a denial of service condition.");
  script_tag(name:"affected", value:"Opera version before 11.60 on Linux");
  script_tag(name:"insight", value:"Multiple flwas are due to,

  - Improper handling of the number of .(dot) characters that conventionally
    exist in domain names of different top-level domains.

  - Implementation errors in the 'JavaScript' engine, 'Web Workers' and 'in'
    operator.

  - An error when handling certificate revocation related to 'corner cases'.

  - An error in Dragonfly in opera.");
  script_tag(name:"solution", value:"Upgrade to the Opera version 11.60 or later.");
  script_tag(name:"summary", value:"The host is installed with Opera and is prone to multiple
  vulnerabilities.");
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

if(version_is_less(version:operaVer, test_version:"11.60")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
