###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_linksys_e1500_2500_mul_vuln.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# Linksys E1500/E2500 Multiple Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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

CPE = "cpe:/a:linksys:devices";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107202");
  script_version("$Revision: 11982 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-02 11:57:11 +0530 (Thu, 02 Nov 2017)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Linksys E1500/E2500 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Linksys E1500 or E2500 device and is prone to multiple
vulnerabilities.

  This vulnerability was known to be exploited by the IoT Botnet 'Reaper' in 2017.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is caused by missing input validation in the ping_size
parameter and can be exploited to inject and execute arbitrary shell commands.");

  script_tag(name:"impact", value:"The attacker can start a telnetd or upload and execute a backdoor to
compromise the device.");

  script_tag(name:"affected", value:"Linksys E1500 v1.0.00 build 9, v1.0.04 build 2, v1.0.05 build 1 and
Linksys E2500 v1.0.03, probably all versions up to 2.0.00.");

  script_tag(name:"solution", value:"Update the firmware to version 1.0.06 build 1 for the E1500 model.
  Update the firmware to version 2.0.00 build 1 for the E2500 model.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.s3cur1ty.de/m1adv2013-004");
  script_xref(name:"URL", value:"http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/");
  script_xref(name:"URL", value:"https://community.linksys.com/t5/Wireless-Routers/Re-Reaper-Botnet-Vulnerability/td-p/1224368");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_dependencies("gb_linksys_devices_detect.nasl");
  script_mandatory_keys("Linksys/model", "Linksys/firmware");
  script_require_ports("Services/www", 80, 8080);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

get_app_version(cpe: CPE, nofork: TRUE); # To have a reference to the Detection NVT.

if (!model = get_kb_item("Linksys/model")) exit(0);
if (!firmware = get_kb_item("Linksys/firmware")) exit(0);

if (model == "E1500")
{
    if (version_is_less(version: firmware, test_version: "1.0.06"))
    {
        ver = model + " firmware: " + firmware;
        VULN = TRUE;
        fix = "1.0.06 build 1";
    }
}
else if (model == "E2500")
{
    if (version_is_less(version: firmware, test_version: "2.0.00"))
    {
        ver = model + " firmware: " + firmware;
        VULN = TRUE;
        fix = "2.0.00 build 1";
    }
}

if (VULN)
{
    report = report_fixed_ver(installed_version: ver, fixed_version: "fix");
    security_message(data: report, port: 0);
    exit(0);
}

exit(0);
