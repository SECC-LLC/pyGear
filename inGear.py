import time
import ipaddress
import configparser
import threading
# import pandas as pd
import pycomm3 as pc3
import logging
import logging.handlers
import datetime as dt
import tkinter as tk
# import tkinter.font as tkfnt
from tkinter import ttk
from tkinter import filedialog
# from tkinter import messagebox
# from PIL import Image, ImageTk

#####################################################################################################################
# CONFIG READ

config = configparser.ConfigParser()
config.read('logger.ini')

#####################################################################################################################
# CONFIG UTILS

def conf2list(config_string):
    config_list = config_string.replace("'", '').split(sep=', ')
    return config_list

def list2conf(config_list):
    config_string = ', '.join(config_list)
    return config_string

def tags2conf(tags):
    return str(list(tags))[1:-1]

#####################################################################################################################
# main LOGGING

LOG_FILENAME = config.get('DEFAULT', 'logfilename')

# Set up a specific logger with our desired output level
mainlogger = logging.getLogger('tester')

# Add the log message handler to the logger
log_handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=5*1024*1024, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler.setFormatter(formatter)
mainlogger.addHandler(log_handler)
mainlogger.setLevel(logging.DEBUG)


# This is a class for putting header lines at the start of a file
class HeadyTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):
    def __init__(self, logfile, when, interval, atTime):
        super(HeadyTimedRotatingFileHandler, self).__init__(logfile, when=when, interval=interval, atTime=atTime)
        self._header = ""
        self._log = None

    def doRollover(self):
        super(HeadyTimedRotatingFileHandler, self).doRollover()
        if self._log is not None and self._header != "":
            self._log.info(self._header)

    def setHeader(self, header):
        self._header = header

    def configureHeaderWriter(self, header, log):
        self._header = header
        self._log = log

#####################################################################################################################
# INPUT SANITATION

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

if __name__ == '__main__':
    window = tk.Tk()
    window.title('MCC - PLC Logger')
    window.geometry('800x600')
    window.option_add('*tearOff', False)

    # STYLES
    s = ttk.Style()
    # Create style used by default for all Frames
    s.configure('TFrame', background='#3838ff')
    s.configure('TagList.TFrame', background='#f8c8c8')
    s.configure('TagButtons.TFrame', background='#686838')
    s.configure('LoggerTagList.TFrame', background='#9898c8')
    
    #####################################################################################################################
    # CONFIG IO

    def load_config():
        filename = filedialog.askopenfilename()
        if filename:
            config.read(filename)
            reset_tabs()

    def save_config():
        filename = filedialog.asksaveasfilename()
        if filename:
            # write the file
            with open(filename, 'w') as config_file:
                config.write(config_file)

    #####################################################################################################################
    # threaded LOGGING

    def select_logfile_location():
        global config
        selected_plc_name = tab_control.tab(tab_control.select())['text'].lower()
        log_dir = filedialog.askdirectory()
        if log_dir:
            config[selected_plc_name]['logger_folder'] = log_dir
        print(config[selected_plc_name]['logger_folder'])

    def logging_worker(plc_name, log_cadence, batch_tag=None):
        global config
        selected_plc_config = config[plc_name]
        # create a plc object to read the tags
        plc = pc3.LogixDriver(selected_plc_config.get('PLC_IP_ADDRESS'))
        try:
            plc.open()
            # mark the time
            last_read_dt = dt.datetime.now()
            # get the worker thread name
            t = threading.current_thread()
            t.name = plc_name
            batch_latch = False
            # loop until the plc_name is no longer in the config
            while True:
                # we check to see if the plc name is in the main loggers dictionary
                # if it's not in the dictionary, then the logger config has changed and we should break
                if plc_name in loggers:
                    elapsed = dt.datetime.now() - last_read_dt
                    if plc.connected and (elapsed > dt.timedelta(seconds=log_cadence)):
                        # time to read
                        last_read_dt = dt.datetime.now()
                        tag_read_results = plc.read(*conf2list(selected_plc_config['LOGGER_TAG_LIST']))
                        if batch_tag:
                            # if a batch tag is set, only log data when the batch latch is set
                            res_dict = {tag.tag:tag.value for tag in tag_read_results}
                            if (res_dict[batch_tag]):
                                # if the latch isn't set, set it, otherwise keep logging as usual
                                if not batch_latch:
                                    batch_latch = True
                                loggers[plc_name].info(', '.join([str(tag.value) for tag in tag_read_results]))
                            else:
                                if batch_latch:
                                    # the latch was set, and now the batch is over (tag went false)
                                    batch_latch = False
                                    loggers[plc_name].handlers[0].doRollover()
                                else:
                                    # the latch was not set, the batch tag is not set either
                                    pass
                        else:
                            # if not latching, then log as normal each interval
                            loggers[plc_name].info(', '.join([str(tag.value) for tag in tag_read_results]))
                    else:
                        # plc isnt connected
                        tag_read_results = ''
                    # sleep till next interval
                    time.sleep(0.5)
                else:
                    print('logger not in main. halting...')
                    break
        except Exception as err:
            raise err


    def start_logger(plc_name, log_cadence=6, when='h', interval=1, atTime=None, batch_tag=None):
        global config
        selected_plc_config = config[plc_name]
        log_dir = selected_plc_config['logger_folder']
        print(f'{log_dir}/{plc_name}.log')
        # stop any previously running logger jobs
        stop_logger_thread(plc_name)
        # create a new logger object
        loggers[plc_name] = logging.getLogger(plc_name)
        # we'll use a timed rotating file handler as a default. Hopefully a batch log file doesnt go longer than 4 wks
        log_handler = HeadyTimedRotatingFileHandler(f'{log_dir}/{plc_name}.log', when=when, interval=interval, atTime=atTime)
        # Set the logger header text
        log_handler.configureHeaderWriter(selected_plc_config['LOGGER_TAG_LIST'], loggers[plc_name])
        # use cutom header formatter
        formatter = logging.Formatter('%(asctime)s, %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        log_handler.setFormatter(formatter)
        loggers[plc_name].addHandler(log_handler)
        loggers[plc_name].setLevel(logging.INFO)
        log_handler.doRollover()
        thread = threading.Thread(target=logging_worker, args=(plc_name, log_cadence, batch_tag), daemon=True)
        thread.start()

    def stop_logger_thread(plc_name):
        if plc_name in loggers:
            # close the handlers and remove them from the logger object
            for handler in loggers[plc_name].handlers:
                handler.close()
                loggers[plc_name].removeHandler(handler)
            # remove the logger from the main dict, which signals termination to the thread
            loggers.pop(plc_name, None)
        # wait for the thread to die
        for thread in threading.enumerate():
            if thread.name == plc_name:
                thread.join()

    def stop_all_logger_threads():
        mainlogger.info('CLOSING ALL LOGGER HANDLERS')
        for lggr in loggers:
            for handler in loggers[lggr].handlers:
                handler.close()
                loggers[lggr].removeHandler(handler)
        mainlogger.info('PURGING LOGGGER DICT')
        loggers.clear()
        # do I need to do this?
        # print('STOPPING ALL LOGGER THREADS')
        main_thread = threading.current_thread()
        for thd in threading.enumerate():
            if thd is main_thread:
                continue
            print('Still Running:', thd)


    #####################################################################################################################
    # PLC QUERY

    def query_plc_tags():
        global config
        selected_plc_name = tab_control.tab(tab_control.select())['text'].lower()
        print(selected_plc_name)
        if selected_plc_name == 'live view':
            print('query on live view, ignore')
            return
        selected_plc_config = config[selected_plc_name]

        try:
            with pc3.LogixDriver(selected_plc_config.get('PLC_IP_ADDRESS', '192.168.1.10')) as plc:
                live_conn_mgr[selected_plc_name] = plc
                # retrieve the current config in list format
                mainlogger.debug('Retrieved tag list: {}'.format(list(plc.tags.keys())))

                plc_list = conf2list(tags2conf(plc.tags.keys()))
                log_list = []

                # update the PLC list
                selected_plc_config['PLC_TAG_LIST'] = list2conf(plc_list)
                selected_plc_config['LOGGER_TAG_LIST'] = list2conf(log_list)

                # reload the config
                print('reloading config... ', end='')
                selected_plc_config = config[selected_plc_name]
                print('done')
                plc_taglists[selected_plc_name].set(conf2list(selected_plc_config['PLC_TAG_LIST']))
                log_taglists[selected_plc_name].set(log_list)

        except Exception as err:
            mainlogger.debug('Could not retrieve tag list: {}'.format(err))
            print('no connection')


    def single_read_tags():
        global config
        selected_plc_name = tab_control.tab(tab_control.select())['text'].lower()
        selected_plc_config = config[selected_plc_name]
        start = dt.datetime.now()
        try:
            with pc3.LogixDriver(selected_plc_config.get('PLC_IP_ADDRESS')) as plc:
                mainlogger.info([(tag.tag, tag.value) for tag in plc.read(*conf2list(selected_plc_config['LOGGER_TAG_LIST']))])
        except Exception as err:
            mainlogger.debug('Could not retrieve tag list: {}'.format(err))

    #####################################################################################################################
    # TAG SELECTION BUTTON COMMANDS

    def update_batch_tag_cbo(*args):
        global config
        selected_plc_name = tab_control.tab(tab_control.select())['text'].lower()
        selected_plc_config = config[selected_plc_name]
        log_batch_cbo[selected_plc_name]['values'] = conf2list(selected_plc_config['LOGGER_TAG_LIST'])

    def rename_config():
        rename_dialog()

    def run_config(plc_name = None):
        if plc_name is None:
            # determine the active config name
            plc_name = tab_control.tab(tab_control.select())['text'].lower()
        # filter by log type, then build the args for the logger rotation
        lt_option = log_type[plc_name].get()
        if lt_option == 'HOURLY':
            logger_args = {'when':'h', 'interval':1}
        elif lt_option == 'DAILY':
            logger_args = {'when':'midnight', 'atTime':dt.time(hour=int(log_state_hours[plc_name].get()))}
        elif lt_option == 'WEEKLY':
            # figure out which day to rotate on and at what time
            week_map = {'SUNDAY':'W6', 'MONDAY':'W0', 'TUESDAY':'W1', 'WEDNESDAY':'W2', 'THURSDAY':'W3', 'FRIDAY':'W4', 'SATURDAY':'W5'}
            logger_args = {'when':week_map[log_state_days[plc_name].get()], 'atTime':dt.time(hour=int(log_state_hours[plc_name].get()))}
        elif lt_option == 'BATCH':
            logger_args = {'when':'midnight', 'atTime':dt.time(hour=int(log_state_hours[plc_name].get())), 'batch_tag':log_batch_cbo[plc_name].get()}
        else:
            print('invalid log type!')
            raise Exception('BAD LOG TYPE')
        
        # map how often to record data
        period_map = {'1 SEC':1, '10 SEC':10, '1 MIN':60, '1 HOUR':3600}
        logger_args['log_cadence'] = period_map[log_period[plc_name].get()]
        logger_args['plc_name'] = plc_name

        print(f'Running the config for {plc_name}...')
        start_logger(**logger_args)

    def remove_config():
        # TODO: this needs to get rid of all the entries in the dictionaries toooo
        global config
        # find the selected tab
        selected_tab = tab_control.select()
        # find the selected tab config
        selected_plc_name = tab_control.tab(tab_control.select())['text'].lower()
        # select the previous config
        tab_control.select(tab_control.tabs()[tab_control.index(selected_tab)-1])
        # remove the tab
        tab_control.forget(selected_tab)
        # remove the tab config
        config.pop(selected_plc_name, None)

    def add_selected_tags():
        global config
        selected_plc_idx = tab_control.index(tab_control.select())
        selected_plc_name = tab_control.tab(tab_control.select())['text'].lower()
        selected_plc_config = config[selected_plc_name]
        
        # grab the lbox handles
        log_lbox = log_lboxes[selected_plc_name]
        plc_lbox = plc_lboxes[selected_plc_name]

        # put the lbox contents into a list
        log_list = list(log_lbox.get(0, log_lbox.size()))
        plc_list = list(plc_lbox.get(0, plc_lbox.size()))

        # identify whats been selected from the plc
        sel_idx = plc_lbox.curselection()
        selected_tags = [plc_lbox.get(idx) for idx in sel_idx]

        # shuffle tags around
        log_list.extend(selected_tags)
        [plc_list.remove(tag) for tag in selected_tags]

        # update the internal config
        selected_plc_config['LOGGER_TAG_LIST'] = list2conf(log_list)
        selected_plc_config['PLC_TAG_LIST'] = list2conf(plc_list)

        # update the tkvars
        log_taglists[selected_plc_name].set(log_list)
        plc_taglists[selected_plc_name].set(plc_list)
        log_batch_cbo[selected_plc_name]['values'] = conf2list(selected_plc_config['LOGGER_TAG_LIST'])

    def clear_selected_tags():
        global config
        selected_plc_idx = tab_control.index(tab_control.select())
        selected_plc_name = tab_control.tab(tab_control.select())['text'].lower()
        selected_plc_config = config[selected_plc_name]
        
        # grab the lbox handles
        log_lbox = log_lboxes[selected_plc_name]
        plc_lbox = plc_lboxes[selected_plc_name]

        # put the lbox contents into a list
        log_list = list(log_lbox.get(0, log_lbox.size()))
        plc_list = list(plc_lbox.get(0, plc_lbox.size()))

        # identify whats been selected from the log
        sel_idx = log_lbox.curselection()
        selected_tags = [log_lbox.get(idx) for idx in sel_idx]

        # shuffle tags around
        plc_list.extend(selected_tags)
        [log_list.remove(tag) for tag in selected_tags]

        # update the internal config
        selected_plc_config['LOGGER_TAG_LIST'] = list2conf(log_list)
        selected_plc_config['PLC_TAG_LIST'] = list2conf(plc_list)

        # update the tkvars
        log_taglists[selected_plc_name].set(log_list)
        plc_taglists[selected_plc_name].set(plc_list)
        log_batch_cbo[selected_plc_name]['values'] = conf2list(selected_plc_config['LOGGER_TAG_LIST'])

    def clear_all_tags():
        global config
        selected_plc_idx = tab_control.index(tab_control.select())
        selected_plc_name = tab_control.tab(tab_control.select())['text'].lower()
        selected_plc_config = config[selected_plc_name]
        
        # grab the lbox handles
        log_lbox = log_lboxes[selected_plc_name]
        plc_lbox = plc_lboxes[selected_plc_name]

        # put the lbox contents into a list
        log_list = list(log_lbox.get(0, log_lbox.size()))
        plc_list = list(plc_lbox.get(0, plc_lbox.size()))

        # shuffle tags around
        plc_list.extend(log_list)
        log_list = []

        # update the internal config
        selected_plc_config['LOGGER_TAG_LIST'] = list2conf(log_list)
        selected_plc_config['PLC_TAG_LIST'] = list2conf(plc_list)

        # update the tkvars
        log_taglists[selected_plc_name].set(log_list)
        plc_taglists[selected_plc_name].set(plc_list)
        log_batch_cbo[selected_plc_name]['values'] = conf2list(selected_plc_config['LOGGER_TAG_LIST'])

    def add_all_tags():
        global config
        selected_plc_idx = tab_control.index(tab_control.select())
        selected_plc_name = tab_control.tab(tab_control.select())['text'].lower()
        selected_plc_config = config[selected_plc_name]
        
        # grab the lbox handles
        log_lbox = log_lboxes[selected_plc_name]
        plc_lbox = plc_lboxes[selected_plc_name]

        # put the lbox contents into a list
        log_list = list(log_lbox.get(0, log_lbox.size()))
        plc_list = list(plc_lbox.get(0, plc_lbox.size()))

        # shuffle tags around
        log_list.extend(plc_list)
        plc_list = []

        # update the internal config
        selected_plc_config['LOGGER_TAG_LIST'] = list2conf(log_list)
        selected_plc_config['PLC_TAG_LIST'] = list2conf(plc_list)

        # update the tkvars
        log_taglists[selected_plc_name].set(log_list)
        plc_taglists[selected_plc_name].set(plc_list)
        log_batch_cbo[selected_plc_name]['values'] = conf2list(selected_plc_config['LOGGER_TAG_LIST'])


    #####################################################################################################################
    # DIALOG - IP ADDRESS

    def connect_ip():
        global config
        selected_plc_name = tab_control.tab(tab_control.select())['text'].lower()
        
        def dismiss(dlg_ip: str):
            dlg.grab_release()
            dlg.destroy()
            if is_valid_ip(dlg_ip):
                mainlogger.debug(f'Valid IP ({dlg_ip}), connecting...')
                print(f'VALID IP - {dlg_ip}')
                if config[selected_plc_name]['PLC_IP_ADDRESS']:
                    config[selected_plc_name]['PLC_IP_ADDRESS'] = dlg_ip
                else:
                    config['default']['PLC_IP_ADDRESS'] = dlg_ip
                update_status()
            else:
                mainlogger.debug(f'Valid IP ({dlg_ip}), connecting...')
                print(f'INVALID IP - {dlg_ip}')

        dlg = tk.Toplevel(window)
        dlg.geometry('200x100+15+60')
        dlg_ip = tk.StringVar()
        lbl_IP = tk.Label(master=dlg, text=f'{selected_plc_name} IP Address', font=('', 10), borderwidth=1)
        lbl_IP.pack(fill=tk.X, expand=True)
        entry_IP = ttk.Entry(dlg, textvariable=dlg_ip)
        entry_IP.pack(fill=tk.X, expand=True)
        btn_dismiss = ttk.Button(dlg, text="Done", command=lambda: dismiss(dlg_ip.get()))
        btn_dismiss.pack(fill=tk.X, expand=True)
        dlg.bind('<Return>', lambda event: dismiss(dlg_ip.get()))
        dlg.protocol("WM_DELETE_WINDOW", lambda: dismiss(dlg_ip.get())) # intercept close button
        dlg.transient(window)   # dialog window is related to main
        dlg.wait_visibility() # can't grab until window appears, so we wait
        dlg.grab_set()        # ensure all input goes to our window
        entry_IP.focus_set()
        dlg.wait_window()     # block until window is destroyed


    #####################################################################################################################
    # DIALOG - RENAME
    
    def rename_dialog():
        global config
        selected_plc_name = tab_control.tab(tab_control.select())['text'].lower()
        
        def dismiss(*args):
            dlg.grab_release()
            dlg.destroy()
            for dictionary in [config, log_taglists, plc_taglists, plc_lboxes, log_lboxes, log_batch_tag, log_batch_cbo, log_type, log_state_hours, log_state_days, log_period]:
                dictionary[dlg_plc_name.get()] = dictionary[selected_plc_name]
                dictionary.pop(selected_plc_name, None)
            # TODO: Address renaming a config while a logger thread is running!

            tab_control.tab(tab_control.select(), text=dlg_plc_name.get())


        dlg = tk.Toplevel(window)
        dlg.geometry('200x140+15+60')
        dlg_plc_name = tk.StringVar()
        lbl_plc_name = tk.Label(master=dlg, text='New PLC Config Name', font=('', 10), borderwidth=1)
        lbl_plc_name.pack(fill=tk.X, expand=True)
        entry_plc_name = ttk.Entry(dlg, textvariable=dlg_plc_name)
        entry_plc_name.pack(fill=tk.X, expand=True)
        btn_dismiss = ttk.Button(dlg, text="Done", command=dismiss)
        btn_dismiss.pack(fill=tk.X, expand=True)
        dlg.bind('<Return>', dismiss)
        dlg.protocol("WM_DELETE_WINDOW", dismiss) # intercept close button
        dlg.transient(window)   # dialog window is related to main
        dlg.wait_visibility() # can't grab until window appears, so we wait
        dlg.grab_set()        # ensure all input goes to our window
        entry_plc_name.focus_set()
        dlg.wait_window()     # block until window is destroyed
        return dlg_plc_name.get()


    #####################################################################################################################
    # DIALOG - NEW FRAME
    
    def new_frame_dialog():
        global config
        
        def dismiss(dlg_ip: str):
            dlg.grab_release()
            dlg.destroy()
            if is_valid_ip(dlg_ip):
                mainlogger.debug(f'Valid IP ({dlg_ip}), connecting...')
                # if the config exists
                if dlg_plc_name.get() in config:
                    config[dlg_plc_name.get()]['PLC_IP_ADDRESS'] = dlg_ip
                else:
                    config[dlg_plc_name.get()] = {'PLC_IP_ADDRESS':dlg_ip, 'plc_tag_list':'', 'logger_tag_list':''}
                update_status()
            else:
                mainlogger.debug(f'INVALID IP ({dlg_ip})')

        dlg = tk.Toplevel(window)
        dlg.geometry('200x140+15+60')
        dlg_plc_name = tk.StringVar()
        lbl_plc_name = tk.Label(master=dlg, text='New PLC Config Name', font=('', 10), borderwidth=1)
        lbl_plc_name.pack(fill=tk.X, expand=True)
        entry_plc_name = ttk.Entry(dlg, textvariable=dlg_plc_name)
        entry_plc_name.pack(fill=tk.X, expand=True)
        dlg_ip = tk.StringVar()
        lbl_IP = tk.Label(master=dlg, text='New PLC IP Address', font=('', 10), borderwidth=1)
        lbl_IP.pack(fill=tk.X, expand=True)
        entry_IP = ttk.Entry(dlg, textvariable=dlg_ip)
        entry_IP.pack(fill=tk.X, expand=True)
        btn_dismiss = ttk.Button(dlg, text="Done", command=lambda: dismiss(dlg_ip.get()))
        btn_dismiss.pack(fill=tk.X, expand=True)
        dlg.bind('<Return>', lambda event: dismiss(dlg_ip.get()))
        dlg.protocol("WM_DELETE_WINDOW", lambda: dismiss(dlg_ip.get())) # intercept close button
        dlg.transient(window)   # dialog window is related to main
        dlg.wait_visibility() # can't grab until window appears, so we wait
        dlg.grab_set()        # ensure all input goes to our window
        entry_plc_name.focus_set()
        dlg.wait_window()     # block until window is destroyed
        return dlg_plc_name.get()

    #####################################################################################################################
    # NOTEBOOK HANDLER

    def handle_tab_change(event, *args):
        # index of currently selected tab
        new_tab_idx = tab_control.index(tab_control.select())
        # index of add tab button
        add_tab_idx = tab_control.index(tab_add)
        # index of live view tab
        live_tab_idx = tab_control.index(tab_live)
        # determine if we're switching tabs or adding a new one
        if new_tab_idx == add_tab_idx:
            new_tab()
        elif new_tab_idx == live_tab_idx:
            pass
            # update_live()
        else:
            update_status()

    def new_tab(*args):
        # index of currently selected tab
        new_tab_idx = tab_control.index(tab_control.select())
        new_config_name = new_frame_dialog()
        # create a new logger frame
        new_tag_frame = gen_new_tab(new_config_name)
        # add it to the notebook container
        tab_control.insert(new_tab_idx, new_tag_frame, text=new_config_name.upper())
        # move to the new frame
        tab_control.select(new_tag_frame)

    #####################################################################################################################
    # STATUS BAR

    def update_status(*args):
        selected_plc_name = tab_control.tab(tab_control.select())['text'].lower()
        if selected_plc_name != '+':
            status_IP = config[selected_plc_name].get('plc_ip_address')
            status_bar.config(text=f'IP Address: {status_IP}')

    #####################################################################################################################
    # TAB SETUP
    def gen_new_tab(plc_name = 'new_plc'):
        global config
        new_tab = ttk.Frame(tab_control)

        #####################################################################################################################
        # UI VARS
        plc_taglists[plc_name] = tk.Variable()
        log_taglists[plc_name] = tk.Variable()
        log_period[plc_name] = tk.Variable()
        log_type[plc_name] = tk.Variable()
        log_state_days[plc_name] = tk.Variable()
        log_state_hours[plc_name] = tk.Variable()
        log_batch_tag[plc_name] = tk.Variable()

        #####################################################################################################################
        # Selector Tab
        new_tab.columnconfigure(0, weight=5)
        new_tab.columnconfigure(1, weight=2)
        new_tab.columnconfigure(2, weight=5)
        new_tab.rowconfigure(0, weight=1)
        frm_PLCtags = ttk.Frame(master=new_tab, relief=tk.RAISED, borderwidth=1, padding=[10,5], style='TagList.TFrame')
        frm_PLCtags.grid(row=0, column=0, sticky='news')
        frm_TagBtns = ttk.Frame(master=new_tab, relief=tk.RAISED, borderwidth=1, padding=[10,0], style='TagButtons.TFrame')
        frm_TagBtns.grid(row=0, column=1, sticky='news')
        frm_LogTags = ttk.Frame(master=new_tab, relief=tk.RAISED, borderwidth=1, padding=[10,5], style='LoggerTagList.TFrame')
        frm_LogTags.grid(row=0, column=2, sticky='news')

        #####################################################################################################################
        # Selector Tab - PLC
        lblPLCtag = tk.Label(master=frm_PLCtags, text='PLC Tags', font=('', 16), borderwidth=1)
        lblPLCtag.pack(fill=tk.X, expand=True)

        plc_lboxes[plc_name] = tk.Listbox(master=frm_PLCtags, listvariable=plc_taglists[plc_name], height=80, selectmode='extended')
        plc_lboxes[plc_name].pack(fill=tk.BOTH, expand=True)

        #####################################################################################################################
        # Selector Tab - BUTTONS
        btn_runconf = tk.Button(master=frm_TagBtns, text='Run Config', command=run_config, font=('', 12))
        btn_runconf.pack(fill=tk.X, expand=True)
        # btn_stop_logger = tk.Button(master=frm_TagBtns, text='Stop All Loggers', command=stop_all_logger_threads, font=('', 12))
        # btn_stop_logger.pack(fill=tk.X, expand=True)
        btn_edit = tk.Button(master=frm_TagBtns, text='Rename Config', command=rename_config, font=('', 12))
        btn_edit.pack(fill=tk.X, expand=True)
        sep = ttk.Separator(frm_TagBtns, orient=tk.HORIZONTAL)
        sep.pack(fill=tk.X, expand=True)
        # Logger Config
        lf_config = ttk.Labelframe(frm_TagBtns, text='Logger Cadence')
        lf_config.pack(fill=tk.X, expand=True)
        lf_config.columnconfigure(0, weight=1)
        lf_config.columnconfigure(1, weight=2)
        lf_config.rowconfigure(0, weight=1)
        lf_config.rowconfigure(1, weight=1)
        lf_config.rowconfigure(2, weight=1)
        lf_config.rowconfigure(3, weight=1)
        lf_config.rowconfigure(4, weight=1)
        lbl_cadence_type = tk.Label(lf_config, text='Log Type')
        lbl_cadence_type.grid(row=0, column=0, sticky='nw')
        cbo_cadence_type = ttk.Combobox(lf_config, values=('HOURLY', 'DAILY', 'WEEKLY', 'BATCH'), textvariable=log_type[plc_name], state='readonly')
        cbo_cadence_type.set(config[plc_name].get('log_cadence','HOURLY'))
        cbo_cadence_type.grid(row=0, column=1, sticky='news')
        lbl_rotation_day = tk.Label(lf_config, text='Log Rotate Day')
        lbl_rotation_day.grid(row=1, column=0, sticky='nw')
        cbo_rotation_day = ttk.Combobox(lf_config, values=('SUNDAY', 'MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY'), textvariable=log_state_days[plc_name], state='readonly')
        cbo_rotation_day.set(config[plc_name].get('log_start_day','SUNDAY'))
        cbo_rotation_day.grid(row=1, column=1, sticky='news')
        lbl_rotation_hour = tk.Label(lf_config, text='Log Rotate Hour')
        lbl_rotation_hour.grid(row=2, column=0, sticky='nw')
        cbo_rotation_hour = ttk.Combobox(lf_config, values=tuple(range(0,24)), textvariable=log_state_hours[plc_name], state='readonly')
        cbo_rotation_hour.set(config[plc_name].get('log_start_hour',14))
        cbo_rotation_hour.grid(row=2, column=1, sticky='news')
        lbl_batch_tag = tk.Label(lf_config, text='Batch Tag')
        lbl_batch_tag.grid(row=3, column=0, sticky='nw')
        lbl_period = tk.Label(lf_config, text='Log Period')
        lbl_period.grid(row=4, column=0, sticky='nw')
        cbo_period = ttk.Combobox(lf_config, values=('1 SEC', '10 SEC', '1 MIN', '1 HOUR'), textvariable=log_period[plc_name], state='readonly')
        cbo_period.set(config[plc_name].get('logger_period','10 SEC'))
        cbo_period.grid(row=4, column=1, sticky='news')
        log_batch_cbo[plc_name] = ttk.Combobox(lf_config, values=plc_lboxes[plc_name].get(0, plc_lboxes[plc_name].size()), textvariable=log_batch_tag[plc_name], state='readonly')
        log_batch_cbo[plc_name].grid(row=3, column=1, sticky='news')
        # Tag Buttons
        sep = ttk.Separator(frm_TagBtns, orient=tk.HORIZONTAL)
        sep.pack(fill=tk.X, expand=True)
        btn_add_all = tk.Button(master=frm_TagBtns, text='Add All Tags', command=add_all_tags, font=('', 12))
        btn_add_all.pack(fill=tk.X, expand=True)
        btn_add_sel = tk.Button(master=frm_TagBtns, text='Add Selected Tags', command=add_selected_tags, font=('', 12))
        btn_add_sel.pack(fill=tk.X, expand=True)
        btn_clr_sel = tk.Button(master=frm_TagBtns, text='Clear Selected Tags', command=clear_selected_tags, font=('', 12))
        btn_clr_sel.pack(fill=tk.X, expand=True)
        btn_clr_all = tk.Button(master=frm_TagBtns, text='Clear All Tags', command=clear_all_tags, font=('', 12))
        btn_clr_all.pack(fill=tk.X, expand=True)
        # btn_read = tk.Button(master=frm_TagBtns, text='Read Selected Tags', command=single_read_tags, font=('', 12))
        # btn_read.pack(fill=tk.X, expand=True)
        sep = ttk.Separator(frm_TagBtns, orient=tk.HORIZONTAL)
        sep.pack(fill=tk.X, expand=True)
        btn_remove_config = tk.Button(master=frm_TagBtns, text='Delete Config', command=remove_config, font=('', 12))
        btn_remove_config.pack(fill=tk.X, expand=True)

        #####################################################################################################################
        # Selector Tab - LOGGER
        lbl_LoggerTags = tk.Label(master=frm_LogTags, text='Logger Tags', font=('', 16), borderwidth=1)
        lbl_LoggerTags.pack(fill=tk.X, expand=True)

        log_lboxes[plc_name] = tk.Listbox(master=frm_LogTags, listvariable=log_taglists[plc_name], height=80, selectmode='extended')
        log_lboxes[plc_name].pack(fill=tk.BOTH, expand=True)

        return new_tab

    def reset_tabs():
        if len(tab_control.tabs()) > 2:
            # Get rid of the tabs that already exist
            for tab in tab_control.tabs()[:-2]:
                selected_plc_name = tab_control.tab(tab)['text']
                plc_taglists.pop(selected_plc_name, None)
                log_taglists.pop(selected_plc_name, None)
                plc_lboxes.pop(selected_plc_name, None)
                log_lboxes.pop(selected_plc_name, None)
                tab_control.forget(tab)

        # Build the new tabs from the config
        for idx, section in enumerate(config):
            if section == 'DEFAULT':
                continue
            new_tab = gen_new_tab(section)

            # get the taglists from the config
            selected_plc_config = config[section]
            plc_list = conf2list(selected_plc_config['PLC_TAG_LIST'])
            log_list = conf2list(selected_plc_config['LOGGER_TAG_LIST'])

            # grab the lbox handles
            # log_lbox = log_lboxes[selected_plc_name]
            # plc_lbox = plc_lboxes[selected_plc_name]

            # populate the lboxes from the config
            plc_taglists[section].set(plc_list)
            log_taglists[section].set(log_list)

            log_batch_cbo[section]['values'] = log_list


            tab_control.insert(idx-1, new_tab, text=f'{section}'.upper())
            run_config(section)


        tab_control.select(tab_control.tabs()[0])

        # TODO: This should probablly stop and clear all the logger threads too


    #####################################################################################################################
    # MENUBAR
    # win = tk.Toplevel(window)
    menubar = tk.Menu(window)
    window['menu'] = menubar
    menu_file = tk.Menu(menubar)
    menu_config = tk.Menu(menubar)
    
    menubar.add_cascade(menu=menu_file, label='File')
    menubar.add_cascade(menu=menu_config, label='Config')

    # File Menu
    menu_file.add_command(label='Query PLC Tag List', command=query_plc_tags)
    menu_file.add_command(label='Stop All Loggers', command=stop_all_logger_threads)
    menu_file.add_separator()
    menu_file.add_command(label='Log File Location', command=select_logfile_location)
    menu_file.add_separator()
    menu_file.add_command(label='Close', command=window.destroy)

    # Config Menu
    menu_config.add_command(label='New Config', command=new_tab)
    menu_config.add_command(label='Delete Config', command=remove_config)
    menu_config.add_separator()
    menu_config.add_command(label='Load Config', command=load_config)
    menu_config.add_command(label='Save Config', command=save_config)
    menu_config.add_separator()
    menu_config.add_command(label='Rename Config', command=rename_config)
    menu_config.add_command(label='Set Config IP', command=connect_ip)
    menu_config.add_separator()
    menu_config.add_command(label='Run Config', command=run_config)


    #####################################################################################################################
    # STATUS BAR
    status_bar = tk.Label(window, text='IP Address: ', bd=1, relief=tk.SUNKEN, anchor=tk.W)
    status_bar.pack(side=tk.BOTTOM, fill=tk.X)


    #####################################################################################################################
    # TAB SETUP
    tab_control = ttk.Notebook(window)
    plc_taglists = {}
    log_taglists = {}
    plc_lboxes = {}
    log_lboxes = {}
    log_batch_cbo = {}
    log_period = {}
    log_type = {}
    log_state_days = {}
    log_state_hours = {}
    log_batch_tag = {}
    loggers = {}

    live_frames = {}
    live_labels = {}

    #####################################################################################################################
    # ADD TAB BUTTON
    tab_add = ttk.Frame(tab_control)
    tab_control.add(tab_add, text='+')


    #####################################################################################################################
    # Live Tab
    tab_live = ttk.Frame(tab_control)
    tab_control.add(tab_live, text='Live View')
    
    live_conn_mgr = {}

    tab_control.pack(expand=1, fill='both')
    tab_control.bind('<<NotebookTabChanged>>', handle_tab_change)


    #####################################################################################################################
    # UI UPDATE

    def update_live():
        global config

        for plc_idx, plc_name in enumerate(log_taglists):
            try:
                # check if there's already a labelframe
                if plc_name not in live_frames:
                    # build a labelframe with the tags names on one side and the values next to them
                    section_lf = ttk.Labelframe(tab_live, text=plc_name, padding=10)
                    section_lf.columnconfigure(0, weight=3)
                    section_lf.columnconfigure(1, weight=1)
                    section_lf.pack(fill=tk.X, expand=True)
                    # sep = ttk.Separator(tab_live, orient=tk.HORIZONTAL)
                    # sep.pack(fill=tk.X)
                    live_frames[plc_name] = section_lf
                    live_labels[plc_name] = {}
                log_list = conf2list(config[plc_name]['LOGGER_TAG_LIST'])
                for idx, tag in enumerate(log_list):
                    # check if the labels are already built
                    if tag not in live_labels[plc_name]:
                        # DNE. Build them
                        live_frames[plc_name].rowconfigure(idx, weight=1)
                        lbl_tag = tk.Label(live_frames[plc_name], text=f'{tag}: ')
                        lbl_tag.grid(row=idx, column=0, sticky='nes')
                        lbl_tag_val = tk.Label(live_frames[plc_name], text='N/A', relief='sunken')
                        lbl_tag_val.grid(row=idx, column=1, sticky='news')
                        live_labels[plc_name][tag] = (lbl_tag, lbl_tag_val)
                # we should probably get rid of the tags labels not in the list....
                for tag in list(live_labels[plc_name]):
                    if tag not in log_list:
                        live_labels[plc_name][tag][0].destroy()
                        live_labels[plc_name][tag][1].destroy()
                        live_labels[plc_name].pop(tag, None)
                # now we can assume the labelframes and tag labels exist
                if plc_name in live_conn_mgr:
                    if live_conn_mgr[plc_name].connected:
                        tag_read_results = live_conn_mgr[plc_name].read(*log_list)
                    else:
                        tag_read_results = None
                else:
                    tag_read_results = None
                if tag_read_results:
                    for tag in tag_read_results:
                        live_labels[plc_name][tag.tag][1].config(text=f'{tag.value}')
                else:
                    for tag in live_labels[plc_name]:
                        live_labels[plc_name][tag][0].config(bg='red')
            except Exception as err:
                print('Error: ', err)

        window.after(1000, update_live)

    reset_tabs()
    update_status()
    update_live()
    # query_plc_tags()
    window.mainloop()
