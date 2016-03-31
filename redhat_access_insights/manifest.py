'''
Module responsible for collecting information on commands/files
and whether they were collected or not, and if not, why
'''
import logging
import os


class InsightsManifest(object):
    '''
    Build the report
    '''
    def __init__(self):
        self.okay = []
        self.missed = []

    def report_okay(command, file):
        pass

    def report_miss(command, file, reason):
        pass

    def write_report():
        pass
