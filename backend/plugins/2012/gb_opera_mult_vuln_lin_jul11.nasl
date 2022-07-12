###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln_lin_jul11.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Opera Browser Multiple Vulnerabilities July-11 (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802739");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2011-1337", "CVE-2011-2609", "CVE-2011-2610", "CVE-2011-2611",
                "CVE-2011-2612", "CVE-2011-2613", "CVE-2011-2614", "CVE-2011-2615",
                "CVE-2011-2616", "CVE-2011-2617", "CVE-2011-2618", "CVE-2011-2619",
                "CVE-2011-2620", "CVE-2011-2621", "CVE-2011-2622", "CVE-2011-2623",
                "CVE-2011-2624", "CVE-2011-2625", "CVE-2011-2626", "CVE-2011-2627");
  script_bugtraq_id(48501, 48500, 48556);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-10 11:44:51 +0530 (Tue, 10 Apr 2012)");
  script_name("Opera Browser Multiple Vulnerabilities July-11 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45060");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68323");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unix/1150/");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  and cause a denial of service.");
  script_tag(name:"affected", value:"Opera Web Browser version prior 11.50 on Linux");
  script_tag(name:"insight", value:"For information about vulnerability refer the references.");
  script_tag(name:"solution", value:"Upgrade to Opera Web Browser version 11.50 or later.");
  script_tag(name:"summary", value:"The host is installed with Opera browser and is prone to multiple
  vulnerabilities.");
  script_xref(name:"URL", value:"http://www.opera.com/download/");
  exit(0);
}


include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"11.50")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
