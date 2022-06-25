###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avm_fritz_box_fw_sign_bypass.nasl 11414 2018-09-16 12:02:34Z cfischer $
#
# AVM FRITZ!Box Firmware Signature Bypass
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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

CPE = "cpe:/o:avm:fritz%21_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108462");
  script_version("$Revision: 11414 $");
  script_cve_id("CVE-2014-8872");
  script_name("AVM FRITZ!Box Firmware Signature Bypass");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-16 14:02:34 +0200 (Sun, 16 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-16 13:38:48 +0200 (Sun, 16 Sep 2018)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_avm_fritz_box_detect.nasl");
  script_mandatory_keys("avm/fritz/model", "avm/fritz/firmware_version");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jan/86");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130040/AVM-FRITZ-Box-Firmware-Signature-Bypass.html");

  script_tag(name:"summary", value:"Multiple AVM FRITZ!Box devices are using an improper verification of cryptographic signatures.");

  script_tag(name:"insight", value:"The signature check of FRITZ!Box firmware images is flawed. Malicious
  code can be injected into firmware images without breaking the RSA signature.");

  script_tag(name:"impact", value:"The code will be executed either if a manipulated firmware
  image is uploaded by the victim or if the victim confirms an update on the webinterface during
  a MITM attack.");

  script_tag(name:"vuldetect", value:"Check the AVM FRITZ!OS version.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or the script output
  on the available updates for the matching model.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! fw_version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );
if( ! model = get_kb_item( "avm/fritz/model" ) ) exit( 0 );

# nb: https://seclists.org/fulldisclosure/2015/Jan/86 has a list
# of affected / fixed versions. The list is a bit messy but the
# array above should map the list as good as possible based on
# the provided info.
fixes = make_array("7490", "5.50#-#6.19#-#6.20",
                   "7390", "5.50#-#6.19#-#6.20",
                   "7270 v3", "5.50#-#6.04#-#6.05",
                   "7270 v2", "5.50#-#6.04#-#6.05",
                   "7270 v1","5.50#-#6.04#-#6.05",
                   "7240", "5.50#-#6.04#-#6.05",
                   "6810 LTE", "5.22#-#6.19#-#6.20",
                   "6840 LTE", "5.23#-#6.19#-#6.20");

if( ! fixes[model] ) exit( 99 );
range = fixes[model];
range = split( range, sep:"#-#", keep:FALSE );
if( max_index( range ) != 3 ) exit( 0 );
start = range[0];
end   = range[1];
patch = range[2];

if( version_in_range( version:fw_version, test_version:start, test_version2:end ) ) {
  report  = 'Model:              ' + model + '\n';
  report += 'Installed Firmware: ' + fw_version + '\n';
  report += 'Fixed Firmware:     ' + patch;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );