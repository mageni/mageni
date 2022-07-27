###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ruby_heap_bof_vuln_win_nov13.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Ruby Interpreter Heap Overflow Vulnerability Nov13 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 SecPod, http://www.secpod.com
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
CPE = "cpe:/a:ruby-lang:ruby";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903502");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-4164");
  script_bugtraq_id(63873);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-11-27 20:39:27 +0530 (Wed, 27 Nov 2013)");
  script_name("Ruby Interpreter Heap Overflow Vulnerability Nov13 (Windows)");


  script_tag(name:"summary", value:"The host is installed with Ruby Interpreter and is prone to Heap Overflow
Vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 1.9.3 patchlevel 484, 2.0.0 patchlevel 353, or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"The flaw is due to improper sanitization while processing user supplied
input data during conversion of strings to floating point values.");
  script_tag(name:"affected", value:"Ruby Interpreter version 1.8, 1.9 before 1.9.3 Patchlevel 484, 2.0 before
2.0.0 Patchlevel 353.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to cause denial of service
or potentially the execution of arbitrary code.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/55787");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/89191");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("General");
  script_dependencies("secpod_ruby_detect_win.nasl");
  script_mandatory_keys("Ruby/Win/Installed");
  script_xref(name:"URL", value:"http://www.ruby-lang.org");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

rubyVer = get_app_version(cpe:CPE);

if(rubyVer)
{
  if(version_is_equal(version:rubyVer, test_version:"1.8")||
     version_in_range(version:rubyVer, test_version:"1.9",test_version2:"1.9.3.p483")||
     version_in_range(version:rubyVer, test_version:"2.0",test_version2:"2.0.0.p352"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
