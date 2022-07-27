###################################################################################
# OpenVAS Vulnerability Test
# $Id: gb_activeperl_dos_vuln_jan15_win.nasl 11975 2018-10-19 06:54:12Z cfischer $
#
# Perl Denial of Service Vulnerability Jan 2015 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805416");
  script_version("$Revision: 11975 $");
  script_cve_id("CVE-2014-4330");
  script_bugtraq_id(70142);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-20 12:06:15 +0530 (Tue, 20 Jan 2015)");
  script_name("Perl Denial of Service Vulnerability Jan 2015 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Active Perl
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to improper handling of
  crafted input by Dumper method in Data::Dumper.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to cause a denial of service.");

  script_tag(name:"affected", value:"Perl versions 5.20.1 and earlier");

  script_tag(name:"solution", value:"Upgrade to 5.22.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61441");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/533543/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("ActivePerl/Ver");
  script_xref(name:"URL", value:"http://www.perl.org");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!perlVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:perlVer, test_version:"5.20.1"))
{
  report = 'Installed version: ' + perlVer + '\n' +
           'Fixed version: Not Available\n';
  security_message(data:report);
  exit(0);
}
