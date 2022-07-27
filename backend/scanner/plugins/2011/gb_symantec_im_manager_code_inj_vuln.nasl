# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901186");
  script_version("2021-12-01T11:54:46+0000");
  script_cve_id("CVE-2010-3719");
  script_bugtraq_id(45946);
  script_tag(name:"last_modification", value:"2021-12-02 11:13:31 +0000 (Thu, 02 Dec 2021)");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("Symantec IM Manager <= 8.4.16 'eval()' Code Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/IM/Manager");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code on the system.");

  script_tag(name:"affected", value:"Symantec IM Manager versions 8.4.16 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by an input validation error in the
  'ScheduleTask' method of the 'IMAdminSchedTask.asp' page within the administration console when
  processing a POST variable via an 'eval()' call, which could be exploited by attackers to inject
  and execute arbitrary ASP code by enticing a logged-in console user to visit a malicious link.");

  script_tag(name:"solution", value:"Update to version 8.4.17 or later.");

  script_tag(name:"summary", value:"Symantec IM Manager is prone to a code injection vulnerability.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65040");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0259");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-037");
  script_xref(name:"URL", value:"http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2011&suid=20110131_00");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("Symantec/IM/Manager"))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"8.4.16")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.4.17");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);