###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apple_safari_mult_vuln_july11.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Apple Safari Multiple Vulnerabilities - July 2011
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902543");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_cve_id("CVE-2010-1383", "CVE-2010-1420", "CVE-2011-0214", "CVE-2011-0215",
                "CVE-2011-0216", "CVE-2011-0217", "CVE-2011-0218", "CVE-2011-0219",
                "CVE-2011-0221", "CVE-2011-0222", "CVE-2011-0223", "CVE-2011-0225",
                "CVE-2011-0232", "CVE-2011-0233", "CVE-2011-0234", "CVE-2011-0235",
                "CVE-2011-0237", "CVE-2011-0238", "CVE-2011-0240", "CVE-2011-0241",
                "CVE-2011-0242", "CVE-2011-0244", "CVE-2011-0253", "CVE-2011-0254",
                "CVE-2011-0255", "CVE-2011-1288", "CVE-2011-1453", "CVE-2011-1457",
                "CVE-2011-1462", "CVE-2011-1774", "CVE-2011-1797", "CVE-2011-3443");
  script_bugtraq_id(48820, 48823, 48825, 48827, 48828, 48831, 48832, 48833, 48837,
                    48839, 48840, 48841, 48842, 48843, 48844, 48845, 48846, 48847,
                    48848, 48849, 48850, 48851, 48852, 48853, 48854, 48855, 48856,
                    48857, 48858, 48859, 51035);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple Safari Multiple Vulnerabilities - July 2011");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4808");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2011//Jul/msg00002.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"impact", value:"Successful exploitation may result in information disclosure, remote code
  execution, denial of service, or other consequences.");
  script_tag(name:"affected", value:"Apple Safari versions prior to 5.1");
  script_tag(name:"insight", value:"For more details about the vulnerabilities refer the reference section.");
  script_tag(name:"solution", value:"Upgrade to Apple Safari version 5.1 or later.");
  script_tag(name:"summary", value:"The host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.apple.com/safari/download/");
  exit(0);
}


include("version_func.inc");

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

if(version_is_less(version:safVer, test_version:"5.34.50.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
