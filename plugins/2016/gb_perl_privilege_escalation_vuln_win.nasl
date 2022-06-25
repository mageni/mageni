###################################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_privilege_escalation_vuln_win.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Perl Privilege Escalation Vulnerability (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:perl:perl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809818");
  script_version("$Revision: 12313 $");
  script_cve_id("CVE-2016-1238");
  script_bugtraq_id(92136);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-24 20:21:51 +0530 (Thu, 24 Nov 2016)");
  script_name("Perl Privilege Escalation Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Perl
  and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to several scripts do
  not properly remove . (period) characters from the end of the includes
  directory array.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  local users to gain privileges via a Trojan horse module under the
  current working directory.");

  script_tag(name:"affected", value:"Perl 5.x before 5.22.3-RC2 and
  5.24 before 5.24.1-RC2 on Windows");

  script_tag(name:"solution", value:"Upgrade to 5.22.3-RC2, or 5.24.1-RC2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1355695");
  script_xref(name:"URL", value:"http://www.nntp.perl.org/group/perl.perl5.porters/2016/07/msg238271.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("Perl/Strawberry_or_Active/Installed");
  script_xref(name:"URL", value:"http://www.perl.org");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!perlVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(perlVer =~ "^5\.")
{
  if(version_in_range(version:perlVer, test_version:"5.0", test_version2:"5.22.3.1"))
  {
    fix = "5.22.3-RC2";
    VULN = TRUE;
  }

  else if(version_in_range(version:perlVer, test_version:"5.24", test_version2:"5.24.1.1"))
  {
    fix = "5.24.1-RC2";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:perlVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
