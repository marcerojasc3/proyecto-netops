3- WLC
WLC 9800 — scripts/restore_wlc.py


---
- name: Restore WLC basic config fragments
  hosts: wlc
  gather_facts: no
  vars:
    restore_date: "{{ date | default('YYYY-MM-DD') }}"
    bk_file: "../../outputs/backups/wlc/{{ restore_date }}/{{ inventory_hostname }}.txt"
  tasks:
    - stat: { path: "{{ bk_file }}" }
      register: st
    - fail:
        msg: "Backup WLC no existe {{ bk_file }}"
      when: not st.stat.exists
    - name: Push WLC restore (merge)
      command: >
        python3 ../../scripts/restore_wlc.py
        --host {{ ansible_host }}
        --file {{ bk_file }}

Nota: Lo seguro es restaurar por perfiles/plantillas (RESTCONF/CLI) y no reemplazar todo el running; el script aplica secciones necesarias (WLAN, Profiles, Tags) para volver a un estado operativo.

