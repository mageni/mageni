###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_activeperl_modules_mult_vuln_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Active Perl Modules Multiple Vulnerabilities (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803343");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2011-5060", "CVE-2011-4114", "CVE-2011-3597", "CVE-2011-2939",
                "CVE-2011-2728");
  script_bugtraq_id(49911);
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-03-27 11:15:50 +0530 (Wed, 27 Mar 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Active Perl Modules Multiple Vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46172");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46279");
  script_xref(name:"URL", value:"http://search.cpan.org/dist/Digest/Digest.pm");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=731246");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=753955");
  script_xref(name:"URL", value:"https://rt.cpan.org/Public/Bug/Display.html?id=69560");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("ActivePerl/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause an affected
  application to crash or execute arbitrary perl code.");
  script_tag(name:"affected", value:"Active Perl PAR module before 1.003
  Active Perl Digest module before 1.17
  Active Perl Encode module before 2.44
  Active Perl PAR::Packer module before 1.012 on winows");
  script_tag(name:"insight", value:"The flaws are due to

  - an error in par_mktmpdir function in the 'PAR::Packer' and 'PAR' modules
    creates temporary files in a directory with a predictable name without
    verifying ownership and permissions of this directory.

  - the 'Digest->new()' function not properly sanitising input before using it
    in an 'eval()' call, which can be exploited to inject and execute arbitrary
    perl code.

  - off-by-one error in the decode_xs function in Unicode/Unicode.xs in the
    'Encode' module.

  - An error within the 'File::Glob::bsd_glob()' function when handling the
    GLOB_ALTDIRFUNC flag can be exploited to cause an access violation and
    potentially execute arbitrary code.");
  script_tag(name:"summary", value:"The host is installed with Active Perl and is prone to multiple
  vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Perl 5.14.2 or latr,
  Upgrade to Active Perl PAR module version 1.003 or later
  Upgrade to Active Perl Digest module version 1.17 or later
  Upgrade to Active Perl Encode module version 2.44 or later
  Upgrade Active Perl PAR::Packer module version 1.012 or later  *****
  NOTE: Ignore this warning if above mentioned versions of modules are already installed.
  *****");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.perl.org/get.html");
  exit(0);
}


include("version_func.inc");

## Perl Digest and Perl Encode modules are the default modules in perl
## Test for the perl versions < 5.14.2, because all perl versions are
## having Digest and Encode modules < 1.17 and 2.44 respectively

apVer = get_kb_item("ActivePerl/Ver");
if(apVer)
{
  if(version_is_less(version:apVer, test_version:"5.14.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
