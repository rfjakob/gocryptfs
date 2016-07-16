#!/usr/bin/octave

r=csvread('/tmp/extractloop.csv');
figure('Position',[100,100,1600,800]);
plot(r(:,2), r(:,3)/1024, '-o');
xlabel('seconds')
ylabel('RSS MiB')
grid on;
drawnow;
disp('press enter to exit');
input('');
