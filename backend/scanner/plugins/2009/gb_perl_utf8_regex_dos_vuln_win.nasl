###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_utf8_regex_dos_vuln_win.nasl 12673 2018-12-05 15:02:55Z cfischer $
#
# Perl UTF-8 Regular Expression Processing DoS Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800967");
  script_version("$Revision: 12673 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 16:02:55 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3626");
  script_bugtraq_id(36812);
  script_name("Perl UTF-8 Regular Expression Processing DoS Vulnerability (Windows)");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53939");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/10/23/8");
  script_xref(name:"URL", value:"https://issues.apache.org/SpamAssassin/show_bug.cgi?id=6225");
  script_xref(name:"URL", value:"http://perl5.git.perl.org/perl.git/commit/0abd0d78a73da1c4d13b1c700526b7e5d03b32d4");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("Perl/Strawberry_or_Active/Installed");

  script_tag(name:"impact", value:"Attackers can exploit this issue to crash an affected application via
  specially crafted UTF-8 data leading to Denial of Service.");

  script_tag(name:"affected", value:"Perl version 5.10.1 on Windows.");

  script_tag(name:"insight", value:"An error occurs in Perl while matching an utf-8 character with large or
  invalid codepoint with a particular regular expression.");

  script_tag(name:"summary", value:"The host is installed with Perl and is prone to Denial of Service
  Vulnerability.");

  script_tag(name:"solution", value:"Apply the patch from the referenced link or update to a version
  including this patch.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

apVer = get_kb_item("ActivePerl/Ver");
if(!isnull(apVer) && version_is_equal(version:apVer, test_version:"5.10.1"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

spVer = get_kb_item("Strawberry/Perl/Ver");
if(!isnull(spVer) && version_is_equal(version:spVer, test_version:"5.10.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
