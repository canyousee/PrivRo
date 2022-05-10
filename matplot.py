import numpy as np
import matplotlib.pyplot as plt
from matplotlib import rcParams
from pylab import *

TICK_SIZE = 14
LABEL_SIZE = 17
LEGEND_SIZE = 15

def read():

	name_list = [   'A',
					'C',    
				]
	colorss =	[	'#66CC99', 
					'#EE5C42', 
					'#1E90EE',
					'#9F3ED5'
				]
	families = 	[	'Times New Roman'
				]
	

	time1 = [64.377,	64.792]
	time2 = [8.566,		7.599]
	time3 = [0.104, 	0.104]
	time4 =	[16.179, 	16.276]

	plt.rcParams['xtick.direction'] = 'in'
	plt.rcParams['ytick.direction'] = 'in'
	fig, ax = plt.subplots()

	ax.yaxis.grid(True, linestyle='--', which='major', alpha=0.2)
	plt.grid(axis='y', linestyle='--', linewidth=1, alpha=0.5)
	ax.set_axisbelow(True)
	location = np.arange(len(name_list))

	width = 0.18
	bar_width = 0.02
	
	plt.bar(location[0], time1[0], width=width, alpha=1, 
			color=colorss[0], edgecolor = "white", hatch="//", label = 'Insecure-Baseline')
	plt.bar(location[1], time1[1], width=width, alpha=1, 
			color=colorss[0], edgecolor = "white", hatch="//")

	plt.bar(location[0] + width + bar_width, time2[0], width=width, alpha=1, 
			color=colorss[1], edgecolor = "white",  hatch="..", label = 'Pancake')
	plt.bar(location[1] + width + bar_width, time2[1], width=width, alpha=1,
			color=colorss[1], edgecolor = "white",  hatch="..")

	plt.bar(location[0] + 2*(width + bar_width), time3[0], width=width, alpha=1,
			color=colorss[2], edgecolor = "white",  hatch="xx", label = 'PathORAM')
	plt.bar(location[1] + 2*(width + bar_width), time3[1], width=width, alpha=1,
			color=colorss[2], edgecolor = "white",  hatch="xx")

	plt.bar(location[0] + 3*(width + bar_width), time4[0], width=width, alpha=1, 
			color=colorss[3], edgecolor = "white",  hatch="\\\\", label = 'Our Design')
	plt.bar(location[1] + 3*(width + bar_width), time4[1], width=width, alpha=1,
			color=colorss[3], edgecolor = "white",  hatch="\\\\")

	plt.ylim(pow(10,-2), pow(10,-2)+0.001)
	label_list  = [0.30, 1.30]
	
	plt.xticks(label_list, name_list, fontsize = TICK_SIZE, )
	plt.yticks([pow(10,i) for i in range(-2,4,1)],fontsize = TICK_SIZE)
	plt.yscale('log')

	plt.legend(loc='upper right', ncol = 1, fontsize = 13)
	plt.ylabel('Throughput (KOps)', fontsize = LABEL_SIZE)
	plt.xlabel('YCSB Workload', fontsize = LABEL_SIZE)

	plt.rcParams['font.family'] = 'sans-serif'
	plt.rcParams['font.sans-serif'] = ['Times New Roman']

	plt.tick_params(axis = 'both',bottom = False, top = False, left = False, right = False)
	minorticks_off()
	
	s_width = 1.5
	px = plt.gca()
	px.spines['left'].set_linewidth(s_width)
	px.spines['right'].set_linewidth(s_width)
	px.spines['top'].set_linewidth(s_width)
	px.spines['bottom'].set_linewidth(s_width)
	plt.tight_layout()
	plt.show()

if __name__ == '__main__':
	read()
	