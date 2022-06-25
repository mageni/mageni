###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vrealize_log_insight_VMSA-2016-0008.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# VMSA-2016-0008: VMware vRealize Log Insight addresses important and moderate security issues.
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
###############################################################################

CPE = 'cpe:/a:vmware:vrealize_log_insight';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105752");
  script_cve_id("CVE-2016-2081", "CVE-2016-2082");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12431 $");
  script_name("VMSA-2016-0008: VMware vRealize Log Insight addresses important and moderate security issues");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0008.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"a. Important stored cross-site scripting issue in VMware vRealize Log Insight
VMware vRealize Log Insight contains a vulnerability that may allow for a stored cross-site scripting attack. Exploitation of this issue may lead to the hijack of an authenticated user's session.

b. Moderate cross-site request forgery issue in VMware vRealize Log Insight
VMware vRealize Log Insight contains a vulnerability that may allow for a cross-site request forgery attack. Exploitation of this issue may lead to an attacker replacing trusted content in the Log Insight UI without the user's authorization.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware vRealize Log Insight addresses important and moderate security issues.");

  script_tag(name:"affected", value:"VMware vRealize Log Insight prior to 3.3.2");

  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-10 12:19:55 +0200 (Fri, 10 Jun 2016)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vrealize_log_insight_version.nasl");
  script_mandatory_keys("vmware/vrealize_log_insight/version");

 exit(0);

}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version_is_less( version:version, test_version:"3.3.2" ) ) fix = "3.3.2 Build 3951163";

if( version == "3.3.2" )
{
  build = get_kb_item("vmware/vrealize_log_insight/build");
  if( build && int( build ) > 0 )
    if( int( build ) < int( 3951163 ) ) fix = '3.3.2 Build 3951163';
}

if( fix )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit(0);
}

exit( 99 );
