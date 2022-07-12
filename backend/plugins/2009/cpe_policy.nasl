###############################################################################
# OpenVAS Vulnerability Test
# $Id: cpe_policy.nasl 11665 2018-09-28 07:14:18Z cfischer $
#
# CPE-based Policy Check
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100353");
  script_version("$Revision: 11665 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 09:14:18 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-11-20 12:35:38 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("CPE-based Policy Check");
  script_category(ACT_END);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("cpe_inventory.nasl");
  script_mandatory_keys("cpe_inventory/available");

  #  script_add_preference(name:"Single CPE", value:"cpe:/", type:"entry");
  #  script_add_preference(name:"CPE List", value:"", type:"file");
  #  script_add_preference(name:"Severity", type:"radio", value:"High;Medium;Low");
  #  script_add_preference(name:"Severity upon", type:"radio", value:"present;missing;all missing");

  script_tag(name:"summary", value:"This NVT is running CPE-based Policy Checks.

  ATTENTION: This NVT is deprecated. Please use the new set of 4 NVTs to handle
  CPE policies which are to be found in the family 'Policy'.");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"qod_type", value:"general_note");

  exit(0);
}

exit(66);
