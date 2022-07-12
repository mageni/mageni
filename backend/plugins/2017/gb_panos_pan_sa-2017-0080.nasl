###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panos_pan_sa-2017-0080.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# Palo Alto Networks PAN-OS CVE-2017-7216 Information Disclosure Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/o:paloaltonetworks:pan-os';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107162");
  script_version("$Revision: 14175 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-05-02 11:40:28 +0200 (Tue, 02 May 2017)");
  script_cve_id("CVE-2017-7126");
  script_bugtraq_id(97590);

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"package");
  script_name("Palo Alto Networks PAN-OS CVE-2017-7216 Information Disclosure Vulnerability");
  script_tag(name:"summary", value:"Palo Alto Networks PAN-OS is prone to an information-disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Management Web Interface does not properly validate specific request parameters which can potentially allow for Information Disclosure.");
  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information that may aid in launching further attacks.");
  script_tag(name:"affected", value:"Palo Alto Networks PAN-OS 7.1.8 and prior versions are vulnerable");
  script_tag(name:"solution", value:"Update to Paloaltonetworks PAN-OS 7.1.9.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97590");
  script_xref(name:"URL", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/80");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Palo Alto PAN-OS Local Security Checks");

  script_dependencies("gb_palo_alto_panOS_version.nasl");
  script_mandatory_keys("palo_alto_pan_os/version");

  # Already covered in 2017/gb_panos_pan_sa-2017_0010.nasl
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

include("host_details.inc");
include("version_func.inc");

if(!Ver = get_app_version(cpe:CPE, nofork:TRUE)){
  exit(0);
}

model = get_kb_item( "palo_alto_pan_os/model" );

if (Ver =~ "7\.1" )
{
    if(version_is_less(version: Ver, test_version:"7.1.9"))
    {
      report =  report_fixed_ver(installed_version:Ver, fixed_version:"7.1.9");
      if ( model )
           report += '\nModel:              ' + model;

      security_message(data:report);
      exit( 0 );
    }
}
exit ( 99 );
