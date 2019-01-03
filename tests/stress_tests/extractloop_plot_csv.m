#!/usr/bin/octave

r=csvread('/tmp/extractloop.csv');
figure('Position',[100,100,1600,800]);
[hAx,hLine1,hLine2] = plotyy(r(:,2), r(:,3)/1024, r(:,2), r(:,4));
xlabel('Runtime (seconds)')
set(hLine1, 'LineWidth', 1, 'Marker', 'o', 'MarkerSize', 10)
% LineWidth also sets the marker drawing thickness
set(hLine2, 'LineWidth', 1, 'LineStyle', 'none', 'Marker', '*', 'MarkerSize', 10)
ylabel(hAx(1), 'RSS (MiB)')
ylabel(hAx(2), 'Iteration Time (seconds)')
grid on;
drawnow;
disp('press enter to exit');
input('');
