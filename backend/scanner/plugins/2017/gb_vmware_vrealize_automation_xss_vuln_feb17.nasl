###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vrealize_automation_xss_vuln_feb17.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# VMware vRealize Automation Cross-Site Scripting Vulnerability (VMSA-2016-0003)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:vmware:vrealize_automation';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809794");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2015-2344");
  script_bugtraq_id(84420);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-03 13:26:16 +0530 (Fri, 03 Feb 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("VMware vRealize Automation Cross-Site Scripting Vulnerability (VMSA-2016-0003)");

  script_tag(name:"summary", value:"The host is installed with VMware vRealize
  Automation and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as software does not properly
  filter HTML code from user-supplied input before displaying the input.");

  script_tag(name:"impact", value:"Successful exploitation will result in the
  execution of arbitrary attacker-supplied HTML and script code in the context
  of the affected application, potentially allowing the attacker to steal
  cookie-based authentication credentials or control how the page is rendered
  to the user.");

  script_tag(name:"affected", value:"VMware vRealize Automation versions 6.x
  prior to 6.2.4 on Linux.");

  script_tag(name:"solution", value:"Upgrade to VMware vRealize Automation
  version 6.2.4 Build 3624994 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1035270");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0003.html");
  script_xref(name:"URL", value:"http://pubs.vmware.com/Release_Notes/en/vra/vrealize-automation-624-release-notes.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_dependencies("gb_vmware_vrealize_automation_web_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("vmware/vrealize/automation/version", "Host/runs_unixoide");
  script_xref(name:"URL", value:"http://www.vmware.com/products/vrealize-automation.html");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!vmPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!vmVersion = get_app_version(cpe:CPE, nofork:TRUE, port:vmPort)){
  exit(0);
}

if(vmVersion =~ "^6\." )
{
  if( version_is_less(version:vmVersion, test_version:"6.2.4"))
  {
    VULN = TRUE;
  }

  else if(vmVersion == "6.2.4.0" )
  {
    if(build = get_kb_item( "vmware/vrealize/automation/build"))
    {
      if(int(build) < 3624994)
      {
        VULN = TRUE;
      }
    }
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:vmVersion, fixed_version:"6.2.4 Build 3624994");
    security_message(port:vmPort, data:report);
    exit(0);
  }
}
exit(99);
