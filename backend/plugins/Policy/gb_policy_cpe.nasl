###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_policy_cpe.nasl 11532 2018-09-21 19:07:30Z cfischer $
#
# CPE-based Policy Check
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.103962");
  script_version("$Revision: 11532 $");
  script_name("CPE Policy Check");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 21:07:30 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-01-06 11:30:32 +0700 (Mon, 06 Jan 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_category(ACT_END);
  script_family("Policy");
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH");
  script_dependencies("cpe_inventory.nasl");
  script_mandatory_keys("cpe_inventory/available");

  script_xref(name:"URL", value:"http://docs.greenbone.net/GSM-Manual/gos-4/en/compliance.html#cpe-based");

  script_add_preference(name:"Single CPE", type:"entry", value:"cpe:/");
  script_add_preference(name:"CPE List", type:"file", value:"");
  script_add_preference(name:"Check for", type:"radio", value:"present;missing");

  script_tag(name:"summary", value:"This NVT is running CPE-based Policy Checks.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

# CPE's registered as host details
cpes = host_details_cpes();

single_cpe = script_get_preference("Single CPE");

if (!single_cpe || strlen(single_cpe) < 6) {
  cpes_list = script_get_preference_file_content("CPE List");
  if (!cpes_list) {
    cpes_list = script_get_preference("CPE List");
    if (!cpes_list) {
      exit(0);
    }
    sep = ";";
  } else {
    sep = '\n';
  }

  mycpes_split = split(cpes_list, sep:sep, keep:FALSE);
  mycpes = make_list();

  i = 0;
  foreach mcpe (mycpes_split) {
    # Use get_base_cpe() from host_details.inc to verify the correct syntax of the passed CPE
    if (get_base_cpe(cpe:mcpe)) {
      mycpes[i] = mcpe;
      i++;
    } else {
      set_kb_item(name:"policy/cpe/invalid_list", value:mcpe);
      set_kb_item(name:"policy/cpe/invalid_line/found", value:TRUE);
    }
  }
} else {
  # Use get_base_cpe() from host_details.inc to verify the correct syntax of the passed CPE
  if (get_base_cpe(cpe:single_cpe)) {
    mycpes = make_list(single_cpe);
  } else {
    set_kb_item(name:"policy/cpe/invalid_list", value:single_cpe);
    set_kb_item(name:"policy/cpe/invalid_line/found", value:TRUE);
  }
}

if (!mycpes) {
  exit(0);
}

foreach mycpe (mycpes) {
  found = FALSE;
  foreach cpe (cpes) {
    # Present or possibly present
    if (strlen(cpe) >= strlen(mycpe)) {
      if (ereg(pattern:mycpe, string:cpe)) {
        present += string(mycpe, "|", cpe, "\n");
      }
    } else {
      if (ereg(pattern:cpe, string:mycpe)) {
        poss_present += string(mycpe, "|", cpe, "\n");
      }
    }

    # Missing
    if (!ereg(pattern: "^" + mycpe, string: cpe) && found == FALSE) {
      found = FALSE;
    } else {
      found = TRUE;
    }
  }

  if (!found) {
    missing += string(mycpe, "\n");
  }
}

checkfor = script_get_preference("Check for");
set_kb_item(name:"policy/cpe/checkfor", value:checkfor);

if (present) {
  set_kb_item(name:"policy/cpe/present", value:present);
}

if (poss_present) {
  set_kb_item(name:"policy/cpe/possibly_present", value:poss_present);
}

if (missing) {
  set_kb_item(name:"policy/cpe/missing", value:missing);
}

exit(0);
