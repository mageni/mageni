###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_maketext_mult_code_inje_vuln_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Strawberry Perl Locale::Maketext Module Multiple Code Injection Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803162");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2012-6329");
  script_bugtraq_id(56852);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-01-24 12:42:04 +0530 (Thu, 24 Jan 2013)");
  script_name("Strawberry Perl Locale::Maketext Module Multiple Code Injection Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51498");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80566");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("Strawberry/Perl/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code on
  the system.");
  script_tag(name:"affected", value:"Strawberry Perl version prior to 5.17.7 on Windows");
  script_tag(name:"insight", value:"An improper validation of input by the '_compile()' function which can be
  exploited to inject and execute arbitrary Perl code on the system.");
  script_tag(name:"solution", value:"Upgrade to Strawberry Perl version 5.17.7 or later.");
  script_tag(name:"summary", value:"The host is installed with Strawberry Perl and is prone to multiple code
  injection vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://strawberryperl.com");
  exit(0);
}


include("version_func.inc");

spVer = get_kb_item("Strawberry/Perl/Ver");
if(spVer)
{
  if(version_is_less(version:spVer, test_version:"5.17.7"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
