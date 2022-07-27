################################################################################
# OpenVAS Vulnerability Test
#
# Zimbra Collaboration Suite Multiple Vulnerabilities(02)-May18
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
################################################################################

CPE = "cpe:/a:zimbra:zimbra_collaboration_suite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812894");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-10951", "CVE-2018-10949", "CVE-2018-10950");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-31 11:07:20 +0530 (Thu, 31 May 2018)");
  script_name("Zimbra Collaboration Suite Multiple Vulnerabilities(02)-May18");

  script_tag(name:"summary", value:"This host is running Zimbra Collaboration
  Suite and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to -

  - GetServer, GetAllServers, or GetAllActiveServers call in the Admin SOAP API.

  - Discrepancy between the 'HTTP 404 - account is not active' and
    'HTTP 401 - must authenticate' errors.

  - Verbose error messages containing a stack dump, tracing data, or full
    user-context dump.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to read zimbraSSLPrivateKey, do account enumeration and expose
  information.");

  script_tag(name:"affected", value:"Synacor Zimbra Collaboration Suite (ZCS)
  8.7 before 8.7.11.Patch3 and 8.6 before 8.6.0.Patch10.");

  script_tag(name:"solution", value:"For versions 8.7.x upgrade to version
  8.7.11.Patch3 or later, for versions 8.6.x upgrade to version 8.6.0.Patch10
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  #Patches are undetectable, hence unreliable.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.zimbra.com");
  script_xref(name:"URL", value:"https://bugzilla.zimbra.com/show_bug.cgi?id=108963");
  script_xref(name:"URL", value:"https://bugzilla.zimbra.com/show_bug.cgi?id=108962");
  script_xref(name:"URL", value:"https://bugzilla.zimbra.com/show_bug.cgi?id=108894");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_zimbra_admin_console_detect.nasl");
  script_mandatory_keys("zimbra_web/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!zimport = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:zimport, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(vers=~"^8\.7\." && version_is_less(version:vers, test_version:"8.7.12"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.7.11.Patch3", install_path:path);
  security_message(data:report, port:zimport);
  exit(0);
}

else if(vers == "8.6.0")
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.6.0.Patch10", install_path:path);
  security_message(data:report, port:zimport);
  exit(0);
}
exit(99);
